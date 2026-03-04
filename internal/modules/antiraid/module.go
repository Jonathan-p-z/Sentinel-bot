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
	mu                 sync.Mutex
	counters           map[string]*utils.JoinCounter
	rapidCounters      map[string]*utils.JoinCounter
	newAccountCounters map[string]*utils.JoinCounter
	config             config.Thresholds
	playbook           *playbook.Engine
	audit              *audit.Logger
}

func New(cfg config.Thresholds, playbookEngine *playbook.Engine, auditLogger *audit.Logger) *Module {
	return &Module{
		counters:           make(map[string]*utils.JoinCounter),
		rapidCounters:      make(map[string]*utils.JoinCounter),
		newAccountCounters: make(map[string]*utils.JoinCounter),
		config:             cfg,
		playbook:           playbookEngine,
		audit:              auditLogger,
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

	now := time.Now()
	counter := m.getCounter(guildID)
	count := counter.Add(now)
	rapid := m.getRapidCounter(guildID).Add(now)

	if event.Member != nil && event.Member.User != nil && isRecentlyCreatedAccount(event.Member.User, now, 72*time.Hour) {
		newCount := m.getNewAccountCounter(guildID).Add(now)
		newThreshold := m.config.RaidJoins / 2
		if newThreshold < 2 {
			newThreshold = 2
		}
		if newCount >= newThreshold {
			userID := event.Member.User.ID
			detail := fmt.Sprintf("user=<@%s> count=%d threshold=%d mode=new_accounts", userID, newCount, newThreshold)
			m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "anti_raid", detail)
			return true
		}
	}

	rapidThreshold := m.config.RaidJoins / 2
	if rapidThreshold < 3 {
		rapidThreshold = 3
	}
	if rapid >= rapidThreshold {
		userID := ""
		if event.Member != nil && event.Member.User != nil {
			userID = event.Member.User.ID
		}
		detail := fmt.Sprintf("user=<@%s> count=%d threshold=%d mode=rapid", userID, rapid, rapidThreshold)
		m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "anti_raid", detail)
		return true
	}

	if count < m.config.RaidJoins {
		return false
	}

	userID := ""
	if event.Member != nil && event.Member.User != nil {
		userID = event.Member.User.ID
	}
	detail := fmt.Sprintf("user=<@%s> count=%d threshold=%d", userID, count, m.config.RaidJoins)
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

func (m *Module) getNewAccountCounter(guildID string) *utils.JoinCounter {
	m.mu.Lock()
	defer m.mu.Unlock()
	counter := m.newAccountCounters[guildID]
	if counter == nil {
		counter = utils.NewJoinCounter(15 * time.Second)
		m.newAccountCounters[guildID] = counter
	}
	return counter
}

func isRecentlyCreatedAccount(user *discordgo.User, now time.Time, maxAge time.Duration) bool {
	if user == nil || user.ID == "" {
		return false
	}
	createdAt, err := discordgo.SnowflakeTimestamp(user.ID)
	if err != nil {
		return false
	}
	if createdAt.After(now) {
		return false
	}
	return now.Sub(createdAt) <= maxAge
}

func (m *Module) getRapidCounter(guildID string) *utils.JoinCounter {
	m.mu.Lock()
	defer m.mu.Unlock()
	counter := m.rapidCounters[guildID]
	if counter == nil {
		counter = utils.NewJoinCounter(3 * time.Second)
		m.rapidCounters[guildID] = counter
	}
	return counter
}
