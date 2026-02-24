package antiraid

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/playbook"
	"sentinel-adaptive/internal/utils"

	"github.com/bwmarrin/discordgo"
)

type Module struct {
	mu       sync.Mutex
	counters map[string]*utils.JoinCounter
	config   config.Thresholds
	playbook *playbook.Engine
	audit    *audit.Logger
}

func New(cfg config.Thresholds, playbookEngine *playbook.Engine, auditLogger *audit.Logger) *Module {
	return &Module{
		counters: make(map[string]*utils.JoinCounter),
		config:   cfg,
		playbook: playbookEngine,
		audit:    auditLogger,
	}
}

func (m *Module) HandleJoin(ctx context.Context, session *discordgo.Session, event *discordgo.GuildMemberAdd) bool {
	guildID := ""
	if event.Member != nil {
		guildID = event.Member.GuildID
	}
	if guildID == "" {
		return false
	}

	counter := m.getCounter(guildID)
	count := counter.Add(time.Now())
	if count < m.config.RaidJoins {
		return false
	}

	userID := ""
	if event.Member != nil && event.Member.User != nil {
		userID = event.Member.User.ID
	}
	detail := fmt.Sprintf("type=RAID rule=%djoins/%ds value=%djoins/%ds threshold=%d", m.config.RaidJoins, m.config.RaidWindowSeconds, count, m.config.RaidWindowSeconds, m.config.RaidJoins)
	m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "anti_raid", detail)
	return true
}

func (m *Module) getCounter(guildID string) *utils.JoinCounter {
	m.mu.Lock()
	defer m.mu.Unlock()
	counter := m.counters[guildID]
	if counter == nil {
		counter = utils.NewJoinCounter(time.Duration(m.config.RaidWindowSeconds) * time.Second)
		m.counters[guildID] = counter
	}
	return counter
}
