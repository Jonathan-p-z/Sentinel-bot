package escalation

import (
	"context"
	"fmt"
	"sort"
	"time"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
)

type Module struct {
	cfg   config.EscalationConfig
	store *storage.Store
	audit *audit.Logger
}

func New(cfg config.EscalationConfig, store *storage.Store, auditLogger *audit.Logger) *Module {
	return &Module{cfg: cfg, store: store, audit: auditLogger}
}

// HandleScore checks whether the effective risk score crosses an escalation
// palier and applies the configured action if the per-user cooldown has elapsed.
// Returns true when an action was triggered.
func (m *Module) HandleScore(ctx context.Context, session *discordgo.Session, guildID, userID string, effectiveScore float64, auditOnly bool) bool {
	if !m.cfg.Enabled || len(m.cfg.Paliers) == 0 {
		return false
	}

	palier := m.matchPalier(effectiveScore)
	if palier == nil {
		return false
	}

	// Enforce cooldown.
	if m.cfg.CooldownMinutes > 0 {
		cooldown := time.Duration(m.cfg.CooldownMinutes) * time.Minute
		lastAt, found, err := m.store.GetLastEscalation(ctx, guildID, userID)
		if err == nil && found && time.Since(lastAt) < cooldown {
			return false
		}
	}

	detail := fmt.Sprintf("action=%s score=%.1f palier=%.1f audit=%t", palier.Action, effectiveScore, palier.Score, auditOnly)
	m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "escalation", detail)

	if !auditOnly {
		_ = m.store.AddEscalationLog(ctx, guildID, userID, palier.Action, effectiveScore)
		m.applyAction(ctx, session, guildID, userID, palier)
	}

	return true
}

// matchPalier returns the highest palier whose Score threshold is met.
func (m *Module) matchPalier(score float64) *config.EscalationPalier {
	sorted := make([]config.EscalationPalier, len(m.cfg.Paliers))
	copy(sorted, m.cfg.Paliers)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})
	for i := range sorted {
		if score >= sorted[i].Score {
			return &sorted[i]
		}
	}
	return nil
}

func (m *Module) applyAction(ctx context.Context, session *discordgo.Session, guildID, userID string, palier *config.EscalationPalier) {
	switch palier.Action {
	case "warn":
		// Warn is audit-only; already logged by HandleScore.

	case "mute":
		minutes := palier.DurationMinutes
		if minutes <= 0 {
			minutes = 5
		}
		until := time.Now().Add(time.Duration(minutes) * time.Minute)
		if err := session.GuildMemberTimeout(guildID, userID, &until); err != nil {
			m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "escalation_failed",
				fmt.Sprintf("mute failed: %v", err))
		}

	case "kick":
		if err := session.GuildMemberDelete(guildID, userID); err != nil {
			m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "escalation_failed",
				fmt.Sprintf("kick failed: %v", err))
		}

	case "ban":
		if err := session.GuildBanCreateWithReason(guildID, userID, "Sentinel escalation ban", 0); err != nil {
			m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "escalation_failed",
				fmt.Sprintf("ban failed: %v", err))
		}
	}
}
