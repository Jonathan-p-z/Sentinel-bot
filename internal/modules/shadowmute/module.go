package shadowmute

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
)

type Module struct {
	cfg   config.ShadowMuteConfig
	store *storage.Store
	audit *audit.Logger
}

func New(cfg config.ShadowMuteConfig, store *storage.Store, auditLogger *audit.Logger) *Module {
	return &Module{cfg: cfg, store: store, audit: auditLogger}
}

// HandleMessage checks whether the message author is currently shadow-muted.
// If so, it deletes the message silently, logs the suppression in the audit trail,
// and relogs the message content in the configured admin channel (if any).
// Returns true when a suppression occurred — the caller must return immediately.
func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate) bool {
	if !m.cfg.Enabled {
		return false
	}

	muted, err := m.store.IsShadowMuted(ctx, msg.GuildID, msg.Author.ID)
	if err != nil || !muted {
		return false
	}

	// Silent delete — the user sees the message disappear as if it were a
	// transient client glitch.
	_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)

	detail := fmt.Sprintf("channel=%s content=%s", msg.ChannelID, truncate(msg.Content, 200))
	m.audit.Log(ctx, audit.LevelInfo, msg.GuildID, msg.Author.ID, "shadow_mute_delete", detail)

	m.relayToLogChannel(session, msg)
	return true
}

func (m *Module) relayToLogChannel(session *discordgo.Session, msg *discordgo.MessageCreate) {
	if m.cfg.LogChannelID == "" {
		return
	}

	displayName := msg.Author.Username
	if msg.Author.Discriminator != "" && msg.Author.Discriminator != "0" {
		displayName += "#" + msg.Author.Discriminator
	}

	content := truncate(msg.Content, 1024)
	if content == "" {
		content = "*(contenu vide ou pièce jointe)*"
	}

	embed := &discordgo.MessageEmbed{
		Title:       "Shadow Mute — message supprimé",
		Color:       0x5865F2,
		Description: "",
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Auteur", Value: fmt.Sprintf("<@%s> (%s)", msg.Author.ID, displayName), Inline: true},
			{Name: "Canal", Value: fmt.Sprintf("<#%s>", msg.ChannelID), Inline: true},
			{Name: "Contenu", Value: content, Inline: false},
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	_, _ = session.ChannelMessageSendEmbed(m.cfg.LogChannelID, embed)
}

// AddMute shadow-mutes a user. expiresAt nil means permanent.
func (m *Module) AddMute(ctx context.Context, guildID, userID, mutedBy, reason string, expiresAt *time.Time) error {
	return m.store.AddShadowMute(ctx, guildID, userID, mutedBy, reason, expiresAt)
}

// RemoveMute lifts the shadow mute for a user.
func (m *Module) RemoveMute(ctx context.Context, guildID, userID string) error {
	return m.store.RemoveShadowMute(ctx, guildID, userID)
}

// ListMutes returns the currently active shadow-muted users for a guild.
func (m *Module) ListMutes(ctx context.Context, guildID string) ([]storage.ShadowMuteEntry, error) {
	return m.store.ListShadowMutes(ctx, guildID)
}

// ParseDuration parses duration strings accepted by the slash command.
// Supports Go standard durations (e.g. "30m", "2h") plus "Xd" for days.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	// Standard Go durations: 30m, 2h, 1h30m…
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	// "Xd" — days
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	return 0, fmt.Errorf("durée invalide %q (exemples : 30m, 2h, 7d)", s)
}

func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
