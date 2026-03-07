package antispam

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/risk"
	"sentinel-adaptive/internal/utils"

	"github.com/bwmarrin/discordgo"
)

type Module struct {
	mu      sync.Mutex
	windows map[string]*utils.SlidingWindow
	repeats map[string]*repeatState
	config  config.Thresholds
	risk    *risk.Engine
	audit   *audit.Logger
}

type repeatState struct {
	message string
	count   int
	lastAt  time.Time
}

func New(cfg config.Thresholds, riskEngine *risk.Engine, auditLogger *audit.Logger) *Module {
	return &Module{
		windows: make(map[string]*utils.SlidingWindow),
		repeats: make(map[string]*repeatState),
		config:  cfg,
		risk:    riskEngine,
		audit:   auditLogger,
	}
}

func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate, guildID string, auditOnly bool) (float64, bool, string) {
	key := guildID + ":" + msg.Author.ID
	now := time.Now()
	window := m.getWindow(key)
	count := window.Add(now)
	repeatCount := m.trackRepeat(key, msg.Content, now)
	mentionCount := len(msg.Mentions)

	repeatThreshold := m.config.SpamMessages / 2
	if repeatThreshold < 3 {
		repeatThreshold = 3
	}
	mentionThreshold := 5

	if repeatCount >= repeatThreshold {
		score := m.risk.AddRisk(guildID, msg.Author.ID, 12)
		detail := fmt.Sprintf("user=<@%s> pattern=duplicate repeat=%d threshold=%d message=%q", msg.Author.ID, repeatCount, repeatThreshold, msg.Content)
		m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_spam", detail)
		if !auditOnly {
			_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
		}
		return score, true, detail
	}

	if mentionCount >= mentionThreshold {
		score := m.risk.AddRisk(guildID, msg.Author.ID, 12)
		detail := fmt.Sprintf("user=<@%s> pattern=mention_burst mentions=%d threshold=%d message=%q", msg.Author.ID, mentionCount, mentionThreshold, msg.Content)
		m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_spam", detail)
		if !auditOnly {
			_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
		}
		return score, true, detail
	}

	if count < m.config.SpamMessages {
		return 0, false, ""
	}

	score := m.risk.AddRisk(guildID, msg.Author.ID, 12)
	detail := fmt.Sprintf("user=<@%s> count=%d threshold=%d message=%q", msg.Author.ID, count, m.config.SpamMessages, msg.Content)
	m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_spam", detail)

	if !auditOnly {
		_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
	}
	return score, true, detail
}

func (m *Module) getWindow(key string) *utils.SlidingWindow {
	m.mu.Lock()
	defer m.mu.Unlock()
	window := m.windows[key]
	if window == nil {
		window = utils.NewSlidingWindow(time.Duration(m.config.SpamWindowSeconds) * time.Second)
		m.windows[key] = window
	}
	return window
}

// Cleanup removes map entries whose last activity exceeds the window duration,
// preventing unbounded memory growth on large servers.
func (m *Module) Cleanup() {
	now := time.Now()
	window := time.Duration(m.config.SpamWindowSeconds) * time.Second
	if window <= 0 {
		window = 8 * time.Second
	}
	stale := 5 * window

	m.mu.Lock()
	defer m.mu.Unlock()

	for key, w := range m.windows {
		if now.Sub(w.LastAt()) > stale {
			delete(m.windows, key)
			delete(m.repeats, key)
		}
	}
}

func (m *Module) trackRepeat(key, message string, now time.Time) int {
	normalized := normalizeMessage(message)
	if normalized == "" {
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.repeats[key]
	if state == nil {
		m.repeats[key] = &repeatState{message: normalized, count: 1, lastAt: now}
		return 1
	}

	window := time.Duration(m.config.SpamWindowSeconds) * time.Second
	if window <= 0 {
		window = 8 * time.Second
	}

	if now.Sub(state.lastAt) > window {
		state.message = normalized
		state.count = 1
		state.lastAt = now
		return state.count
	}

	if state.message == normalized {
		state.count++
	} else {
		state.message = normalized
		state.count = 1
	}
	state.lastAt = now
	return state.count
}

func normalizeMessage(message string) string {
	message = strings.TrimSpace(strings.ToLower(message))
	if message == "" {
		return ""
	}
	return strings.Join(strings.Fields(message), " ")
}
