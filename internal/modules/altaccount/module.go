package altaccount

import (
	"context"
	"fmt"
	"strconv"
	"time"
	"unicode"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/modules/escalation"
	"sentinel-adaptive/internal/risk"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
)

// discordEpoch is the Discord snowflake epoch in milliseconds (2015-01-01 UTC).
const discordEpoch = 1420070400000

type Module struct {
	cfg        config.AltAccountConfig
	store      *storage.Store
	risk       *risk.Engine
	audit      *audit.Logger
	escalation *escalation.Module
}

func New(cfg config.AltAccountConfig, store *storage.Store, riskEngine *risk.Engine, auditLogger *audit.Logger, escalationModule *escalation.Module) *Module {
	return &Module{
		cfg:        cfg,
		store:      store,
		risk:       riskEngine,
		audit:      auditLogger,
		escalation: escalationModule,
	}
}

// HandleMemberAdd processes a GuildMemberAdd event and scores the joining user.
// It logs the join, computes a cumulative suspicion score, and acts accordingly:
//
//	score < 40  → nothing
//	score 40-69 → WARN audit log + security channel notification
//	score 70+   → CRIT audit log + escalation engine
func (m *Module) HandleMemberAdd(ctx context.Context, session *discordgo.Session, event *discordgo.GuildMemberAdd) {
	if !m.cfg.Enabled || event.Member == nil || event.Member.User == nil {
		return
	}

	guildID := event.GuildID
	user := event.Member.User
	now := time.Now()

	// Persist the join so future members can use it for timing analysis.
	_ = m.store.AddJoinLog(ctx, guildID, user.ID, user.Username, now)

	score := m.computeScore(ctx, guildID, user, now)
	if score < 40 {
		return
	}

	detail := fmt.Sprintf("alt_account score=%.0f user=%s discriminator=%s", score, user.Username, user.Discriminator)

	if score >= 70 {
		m.audit.Log(ctx, audit.LevelCrit, guildID, user.ID, "alt_account", detail)
		if !m.cfg.LogOnly {
			m.escalation.HandleScore(ctx, session, guildID, user.ID, score, false)
		}
	} else {
		m.audit.Log(ctx, audit.LevelWarn, guildID, user.ID, "alt_account", detail)
	}
}

func (m *Module) computeScore(ctx context.Context, guildID string, user *discordgo.User, now time.Time) float64 {
	var score float64
	score += scoreAccountAge(user.ID, now)
	score += m.scoreJoinTiming(ctx, guildID, now)
	score += m.scoreUsernameSimilarity(ctx, guildID, user.Username)
	score += scoreWeakSignals(user)
	return score
}

// scoreAccountAge derives account creation time from the Discord snowflake and
// returns a risk score based on how new the account is.
func scoreAccountAge(userID string, now time.Time) float64 {
	id, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return 0
	}
	createdMs := int64(id>>22) + discordEpoch
	createdAt := time.Unix(createdMs/1000, (createdMs%1000)*int64(time.Millisecond))
	age := now.Sub(createdAt)

	switch {
	case age < 7*24*time.Hour:
		return 60
	case age < 30*24*time.Hour:
		return 35
	case age < 90*24*time.Hour:
		return 15
	default:
		return 0
	}
}

// scoreJoinTiming returns +30 if 3 or more accounts joined within the last 5 minutes
// (including the current member, already written to join_log).
func (m *Module) scoreJoinTiming(ctx context.Context, guildID string, now time.Time) float64 {
	joins, err := m.store.GetRecentJoins(ctx, guildID, 50)
	if err != nil {
		return 0
	}
	window := now.Add(-5 * time.Minute)
	count := 0
	for _, j := range joins {
		if j.JoinedAt.After(window) {
			count++
		}
	}
	if count >= 3 {
		return 30
	}
	return 0
}

// scoreUsernameSimilarity returns +50 if the username is more than 80% similar
// to any recently banned user (pure-Go Levenshtein, no external library).
func (m *Module) scoreUsernameSimilarity(ctx context.Context, guildID, username string) float64 {
	banned, err := m.store.GetRecentBannedUsers(ctx, guildID, 100)
	if err != nil {
		return 0
	}
	for _, b := range banned {
		if usernameSimilarity(username, b.Username) > 0.8 {
			return 50
		}
	}
	return 0
}

// scoreWeakSignals returns additional points for obvious bot/alt signals.
func scoreWeakSignals(user *discordgo.User) float64 {
	var score float64
	if isAllNumeric(user.Username) {
		score += 20
	}
	// An empty Avatar hash means the user has the default Discord avatar.
	if user.Avatar == "" {
		score += 15
	}
	return score
}

// usernameSimilarity returns a value in [0, 1] where 1.0 means identical.
// Uses normalised Levenshtein distance over Unicode code points.
func usernameSimilarity(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 || len(rb) == 0 {
		return 0
	}
	if a == b {
		return 1.0
	}
	d := levenshtein(ra, rb)
	maxLen := len(ra)
	if len(rb) > maxLen {
		maxLen = len(rb)
	}
	return 1.0 - float64(d)/float64(maxLen)
}

// levenshtein computes the edit distance between two rune slices using the
// standard dynamic-programming algorithm with O(n) space.
func levenshtein(a, b []rune) int {
	la, lb := len(a), len(b)
	// prev[j] = distance between a[:i-1] and b[:j]
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			if a[i-1] == b[j-1] {
				curr[j] = prev[j-1]
			} else {
				curr[j] = 1 + intMin3(prev[j], curr[j-1], prev[j-1])
			}
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func intMin3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// isAllNumeric returns true when s is non-empty and consists entirely of digits.
func isAllNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
