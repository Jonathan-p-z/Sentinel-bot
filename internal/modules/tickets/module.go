package tickets

import (
	"fmt"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

var tierLimits = map[string]int{
	"free":       3,
	"pro":        10,
	"business":   25,
	"enterprise": 50,
}

func TierLimit(plan string) int {
	if limit, ok := tierLimits[plan]; ok {
		return limit
	}
	return tierLimits["free"]
}

const logChannel = "ticket-logs"

func FindTicketCategory(session *discordgo.Session, guildID string) string {
	channels, err := session.GuildChannels(guildID)
	if err != nil {
		return ""
	}
	for _, ch := range channels {
		if ch.Type != discordgo.ChannelTypeGuildCategory {
			continue
		}
		lower := strings.ToLower(ch.Name)
		if strings.Contains(lower, "ticket") || strings.Contains(lower, "staff") {
			return ch.ID
		}
	}
	return ""
}

func EnsureLogChannel(session *discordgo.Session, guildID string) (string, error) {
	channels, err := session.GuildChannels(guildID)
	if err != nil {
		return "", fmt.Errorf("list channels: %w", err)
	}

	for _, ch := range channels {
		if ch.Type == discordgo.ChannelTypeGuildText && ch.Name == logChannel {
			return ch.ID, nil
		}
	}

	perms := []*discordgo.PermissionOverwrite{
		{
			ID:   guildID,
			Type: discordgo.PermissionOverwriteTypeRole,
			Deny: discordgo.PermissionViewChannel,
		},
	}

	ch, err := session.GuildChannelCreateComplex(guildID, discordgo.GuildChannelCreateData{
		Name:                 logChannel,
		Type:                 discordgo.ChannelTypeGuildText,
		PermissionOverwrites: perms,
	})
	if err != nil {
		return "", fmt.Errorf("create log channel: %w", err)
	}
	return ch.ID, nil
}

func CreateTicketChannel(session *discordgo.Session, guildID, categoryID, userID, username string) (*discordgo.Channel, error) {
	name := "ticket-" + sanitizeUsername(username)

	ownerAllow := int64(discordgo.PermissionViewChannel | discordgo.PermissionSendMessages | discordgo.PermissionReadMessageHistory)
	everyoneDeny := int64(discordgo.PermissionViewChannel)

	overwrites := []*discordgo.PermissionOverwrite{
		{
			ID:   guildID,
			Type: discordgo.PermissionOverwriteTypeRole,
			Deny: everyoneDeny,
		},
		{
			ID:    userID,
			Type:  discordgo.PermissionOverwriteTypeMember,
			Allow: ownerAllow,
		},
	}

	if session.State != nil && session.State.User != nil {
		botAllow := int64(discordgo.PermissionViewChannel | discordgo.PermissionSendMessages | discordgo.PermissionReadMessageHistory | discordgo.PermissionManageChannels)
		overwrites = append(overwrites, &discordgo.PermissionOverwrite{
			ID:    session.State.User.ID,
			Type:  discordgo.PermissionOverwriteTypeMember,
			Allow: botAllow,
		})
	}

	data := discordgo.GuildChannelCreateData{
		Name:                 name,
		Type:                 discordgo.ChannelTypeGuildText,
		PermissionOverwrites: overwrites,
	}
	if categoryID != "" {
		data.ParentID = categoryID
	}

	ch, err := session.GuildChannelCreateComplex(guildID, data)
	if err != nil {
		return nil, fmt.Errorf("create ticket channel: %w", err)
	}
	return ch, nil
}

func SendWelcomeMessage(session *discordgo.Session, channelID, userID, lang string) error {
	mention := fmt.Sprintf("<@%s>", userID)

	var welcome, closeLabel, helpLabel string
	switch lang {
	case "en":
		welcome = mention + " — Welcome to your ticket! Describe your issue below."
		closeLabel = "Close ticket"
		helpLabel = "How to describe your issue"
	case "es":
		welcome = mention + " — ¡Bienvenido a tu ticket! Describe tu problema a continuación."
		closeLabel = "Cerrar ticket"
		helpLabel = "Cómo describir tu problema"
	default: // fr
		welcome = mention + " — Bienvenue dans ton ticket ! Décris ton problème ci-dessous."
		closeLabel = "Fermer le ticket"
		helpLabel = "Comment bien décrire ton problème"
	}

	_, err := session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: welcome,
		Components: []discordgo.MessageComponent{
			discordgo.ActionsRow{
				Components: []discordgo.MessageComponent{
					discordgo.Button{
						Label:    closeLabel,
						Style:    discordgo.DangerButton,
						Emoji:    discordgo.ComponentEmoji{Name: "🔒"},
						CustomID: "ticket_close",
					},
					discordgo.Button{
						Label:    helpLabel,
						Style:    discordgo.SecondaryButton,
						Emoji:    discordgo.ComponentEmoji{Name: "📋"},
						CustomID: "ticket_help",
					},
				},
			},
		},
	})
	return err
}

func GenerateTranscript(session *discordgo.Session, channelID string) string {
	msgs, err := session.ChannelMessages(channelID, 100, "", "", "")
	if err != nil || len(msgs) == 0 {
		return "(transcript unavailable)"
	}

	var sb strings.Builder
	// Messages come newest-first; reverse for chronological order.
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		author := "unknown"
		if m.Author != nil {
			author = m.Author.Username
		}
		ts := m.Timestamp.Format(time.RFC3339)
		fmt.Fprintf(&sb, "[%s] %s: %s\n", ts, author, m.Content)
	}
	return sb.String()
}

func PostTranscript(session *discordgo.Session, logChannelID, ticketChannelName, transcript string) {
	header := fmt.Sprintf("**Transcript — #%s**\n", ticketChannelName)
	full := header + "```\n" + transcript + "\n```"
	if len(full) <= 2000 {
		_, _ = session.ChannelMessageSend(logChannelID, full)
		return
	}
	_, _ = session.ChannelMessageSend(logChannelID, header)
	chunks := splitIntoChunks(transcript, 1900)
	for _, chunk := range chunks {
		_, _ = session.ChannelMessageSend(logChannelID, "```\n"+chunk+"\n```")
	}
}

func sanitizeUsername(username string) string {
	lower := strings.ToLower(username)
	var sb strings.Builder
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	result := sb.String()
	if len(result) > 90 {
		result = result[:90]
	}
	return result
}


func splitIntoChunks(s string, size int) []string {
	var chunks []string
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}
