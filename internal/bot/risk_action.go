package bot

import (
	"fmt"
	"time"
)

// ── Risk action deduplication ─────────────────────────
//
// shouldSuppressRiskAction prevents the bot from applying
// the same sanction twice in quick succession for the same
// (guild, user, action, mode) tuple.

type riskActionAggregate struct {
	lastAt time.Time
}

const riskActionCooldown = 5 * time.Minute

// shouldSuppressRiskAction returns true if an identical action
// was already triggered recently. The auditMode flag uses a
// separate key so audit-mode events never collide with live ones.
func (b *Bot) shouldSuppressRiskAction(guildID, userID, action string, auditMode bool) bool {
	mode := "normal"
	if auditMode {
		mode = "audit"
	}
	key := guildID + ":" + userID + ":" + action + ":" + mode

	b.riskActionMu.Lock()
	defer b.riskActionMu.Unlock()

	if agg, ok := b.riskActionAgg[key]; ok {
		if time.Since(agg.lastAt) < riskActionCooldown {
			return true
		}
		agg.lastAt = time.Now()
		return false
	}

	b.riskActionAgg[key] = &riskActionAggregate{lastAt: time.Now()}
	return false
}

// ── Anti-hate escalation ladder ───────────────────────

type hateSanction struct {
	action         string
	timeoutMinutes int
}

// antiHateSanctionForStrike returns the sanction to apply for
// the nth hate-speech strike. Escalation: warn → timeout (5/15/30/60 min) → ban.
func antiHateSanctionForStrike(strike int) hateSanction {
	switch {
	case strike <= 1:
		return hateSanction{action: "warn", timeoutMinutes: 0}
	case strike == 2:
		return hateSanction{action: "timeout", timeoutMinutes: 5}
	case strike == 3:
		return hateSanction{action: "timeout", timeoutMinutes: 15}
	case strike == 4:
		return hateSanction{action: "timeout", timeoutMinutes: 30}
	case strike == 5:
		return hateSanction{action: "timeout", timeoutMinutes: 60}
	default:
		return hateSanction{action: "ban", timeoutMinutes: 0}
	}
}

// antiHateProgressText returns the escalation progress message
// shown to the sanctioned user in their DM.
func antiHateProgressText(lang string, strike int) string {
	// Only French implemented — extend via i18n if needed.
	_ = lang

	if strike >= 6 {
		return fmt.Sprintf("Infraction %d: ban definitif applique.", strike)
	}
	if strike == 5 {
		return fmt.Sprintf("Infraction %d: il te reste 1 seule chance avant le ban definitif.", strike)
	}
	remaining := 5 - strike
	return fmt.Sprintf("Infraction %d: il te reste %d timeouts avant le ban definitif.", strike, remaining)
}

