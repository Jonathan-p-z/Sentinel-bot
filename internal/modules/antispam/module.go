package antispam

import (
	"context"
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
	config  config.Thresholds
	risk    *risk.Engine
	audit   *audit.Logger
}

func New(cfg config.Thresholds, riskEngine *risk.Engine, auditLogger *audit.Logger) *Module {
	return &Module{
		windows: make(map[string]*utils.SlidingWindow),
		config:  cfg,
		risk:    riskEngine,
		audit:   auditLogger,
	}
}

func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate, guildID string, auditOnly bool) (float64, bool) {
	key := guildID + ":" + msg.Author.ID
	window := m.getWindow(key)
	count := window.Add(time.Now())
	if count < m.config.SpamMessages {
		return 0, false
	}

	score := m.risk.AddRisk(guildID, msg.Author.ID, 12)
	m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_spam", "message burst detected")

	if !auditOnly {
		_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
	}
	return score, true
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
