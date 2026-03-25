package tickets

import (
	"fmt"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// tierLimits defines the maximum number of simultaneous open tickets per guild plan.
var tierLimits = map[string]int{
	"free":       3,
	"pro":        10,
	"business":   25,
	"enterprise": 50,
}

// TierLimit returns the ticket limit for a given plan name.
// Defaults to the free limit for unknown plans.
func TierLimit(plan string) int {
	if limit, ok := tierLimits[plan]; ok {
		return limit
	}
	return tierLimits["free"]
}

const (
	categoryName = "📩 Tickets"
	logChannel   = "ticket-logs"
)

// EnsureCategory returns the ID of the "📩 Tickets" category for the guild,
// creating it (invisible to @everyone) if it does not exist.
// The bot receives an explicit ManageRoles overwrite on the category so it can
// set permission overwrites on child channels without hitting Discord's 50013.
func EnsureCategory(session *discordgo.Session, guildID string) (string, error) {
	channels, err := session.GuildChannels(guildID)
	if err != nil {
		return "", fmt.Errorf("list channels: %w", err)
	}

	for _, ch := range channels {
		if ch.Type == discordgo.ChannelTypeGuildCategory && ch.Name == categoryName {
			return ch.ID, nil
		}
	}

	botID := session.State.User.ID

	perms := []*discordgo.PermissionOverwrite{
		// @everyone: deny view so the category and its children are hidden by default.
		{
			ID:   guildID,
			Type: discordgo.PermissionOverwriteTypeRole,
			Deny: discordgo.PermissionViewChannel,
		},
		// Bot: explicit allow so it has ViewChannel + ManageChannels + ManageRoles
		// in the category context, which Discord requires to set overwrites on child channels.
		{
			ID:   botID,
			Type: discordgo.PermissionOverwriteTypeMember,
			Allow: discordgo.PermissionViewChannel |
				discordgo.PermissionManageChannels |
				discordgo.PermissionManageRoles,
		},
	}

	cat, err := session.GuildChannelCreateComplex(guildID, discordgo.GuildChannelCreateData{
		Name:                 categoryName,
		Type:                 discordgo.ChannelTypeGuildCategory,
		PermissionOverwrites: perms,
	})
	if err != nil {
		return "", fmt.Errorf("create category: %w", err)
	}
	return cat.ID, nil
}

// EnsureLogChannel returns the ID of #ticket-logs for the guild, creating it
// (staff-only via ManageGuild permission) if it does not exist.
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

	// Hidden from @everyone, visible only to roles with ManageGuild.
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

// CreateTicketChannel creates a ticket text channel inside the tickets category.
// Staff visibility is inherited from the category permissions; only two explicit
// overwrites are added: @everyone deny, and the ticket owner allow.
func CreateTicketChannel(session *discordgo.Session, guildID, categoryID, userID, username string, logger *zap.Logger) (*discordgo.Channel, error) {
	name := "ticket-" + sanitizeUsername(username)

	perms := []*discordgo.PermissionOverwrite{
		// @everyone: deny view — channel is hidden by default.
		{
			ID:   guildID,
			Type: discordgo.PermissionOverwriteTypeRole,
			Deny: discordgo.PermissionViewChannel,
		},
		// Ticket owner: allow view + send + history.
		{
			ID:    userID,
			Type:  discordgo.PermissionOverwriteTypeMember,
			Allow: discordgo.PermissionViewChannel | discordgo.PermissionSendMessages | discordgo.PermissionReadMessageHistory,
		},
	}

	botID := ""
	if session.State != nil && session.State.User != nil {
		botID = session.State.User.ID
	}

	logger.Info("ticket channel create — pre-API call",
		zap.String("guild_id", guildID),
		zap.String("category_id", categoryID),
		zap.String("bot_id", botID),
		zap.String("owner_id", userID),
		zap.String("channel_name", name),
		zap.Array("overwrites", zapOverwrites(perms)),
	)

	ch, err := session.GuildChannelCreateComplex(guildID, discordgo.GuildChannelCreateData{
		Name:                 name,
		Type:                 discordgo.ChannelTypeGuildText,
		ParentID:             categoryID,
		PermissionOverwrites: perms,
	})
	if err != nil {
		return nil, fmt.Errorf("create ticket channel: %w", err)
	}
	return ch, nil
}

// zapOverwrites implements zap.ArrayMarshaler to log permission overwrites.
type zapOverwrites []*discordgo.PermissionOverwrite

func (z zapOverwrites) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, o := range z {
		t := "role"
		if o.Type == discordgo.PermissionOverwriteTypeMember {
			t = "member"
		}
		enc.AppendString(fmt.Sprintf("{id:%s type:%s allow:%d deny:%d}", o.ID, t, o.Allow, o.Deny))
	}
	return nil
}

// SendWelcomeMessage posts the welcome embed with action buttons into the ticket channel.
func SendWelcomeMessage(session *discordgo.Session, channelID, userID, lang string) error {
	mention := fmt.Sprintf("<@%s>", userID)

	var welcome, closeLabel, helpLabel string
	switch lang {
	case "en":
		welcome = mention + " — Welcome to your ticket! Describe your issue below."
		closeLabel = "🔒 Close ticket"
		helpLabel = "📋 How to describe your issue"
	case "es":
		welcome = mention + " — ¡Bienvenido a tu ticket! Describe tu problema a continuación."
		closeLabel = "🔒 Cerrar ticket"
		helpLabel = "📋 Cómo describir tu problema"
	default: // fr
		welcome = mention + " — Bienvenue dans ton ticket ! Décris ton problème ci-dessous."
		closeLabel = "🔒 Fermer le ticket"
		helpLabel = "📋 Comment bien décrire ton problème"
	}

	_, err := session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: welcome,
		Components: []discordgo.MessageComponent{
			discordgo.ActionsRow{
				Components: []discordgo.MessageComponent{
					discordgo.Button{
						Label:    closeLabel,
						Style:    discordgo.DangerButton,
						CustomID: "ticket_close",
					},
					discordgo.Button{
						Label:    helpLabel,
						Style:    discordgo.SecondaryButton,
						CustomID: "ticket_help",
					},
				},
			},
		},
	})
	return err
}

// GenerateTranscript fetches up to 100 messages from the channel and formats
// them as a plain-text transcript.
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

// PostTranscript posts the transcript text to the log channel.
func PostTranscript(session *discordgo.Session, logChannelID, ticketChannelName, transcript string) {
	header := fmt.Sprintf("**Transcript — #%s**\n", ticketChannelName)
	// Discord message limit is 2000 chars; split if needed.
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

// ── Helpers ───────────────────────────────────────────────────────────────────

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
