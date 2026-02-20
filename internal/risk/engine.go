package risk

import (
	"math"
	"sort"
	"sync"
	"time"

	"sentinel-adaptive/internal/config"
)

type entry struct {
	score      float64
	lastUpdate time.Time
}

type Engine struct {
	mu      sync.RWMutex
	cfg     config.RiskConfig
	clock   Clock
	entries map[string]*entry
}

type ScoreEntry struct {
	UserID string
	Score  float64
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func NewEngine(cfg config.RiskConfig) *Engine {
	engine := &Engine{
		cfg:     cfg,
		clock:   realClock{},
		entries: make(map[string]*entry),
	}
	return engine
}

func (e *Engine) WithClock(clock Clock) {
	e.clock = clock
}

func (e *Engine) AddRisk(guildID, userID string, delta float64) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := guildID + ":" + userID
	now := e.clock.Now()

	item := e.entries[key]
	if item == nil {
		item = &entry{score: 0, lastUpdate: now}
		e.entries[key] = item
	}

	item.score = e.decay(item.score, item.lastUpdate, now)
	item.score = math.Max(0, item.score+delta)
	item.lastUpdate = now

	return item.score
}

func (e *Engine) GetScore(guildID, userID string) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := guildID + ":" + userID
	item := e.entries[key]
	if item == nil {
		return 0
	}

	now := e.clock.Now()
	if e.isExpired(item.lastUpdate, now) {
		delete(e.entries, key)
		return 0
	}

	item.score = e.decay(item.score, item.lastUpdate, now)
	item.lastUpdate = now
	return item.score
}

func (e *Engine) EffectiveScore(riskScore, trustScore float64) float64 {
	return math.Max(0, riskScore-(trustScore*e.cfg.TrustWeight))
}

func (e *Engine) Reset(guildID, userID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := guildID + ":" + userID
	delete(e.entries, key)
}

func (e *Engine) decay(score float64, lastUpdate, now time.Time) float64 {
	minutes := now.Sub(lastUpdate).Minutes()
	if minutes <= 0 {
		return score
	}
	decayed := score - (minutes * e.cfg.DecayPerMinute)
	if decayed < 0 {
		return 0
	}
	return decayed
}

func (e *Engine) isExpired(lastUpdate, now time.Time) bool {
	if e.cfg.TTLMinutes <= 0 {
		return false
	}
	return now.Sub(lastUpdate) > (time.Duration(e.cfg.TTLMinutes) * time.Minute)
}

func (e *Engine) Top(guildID string, limit int) []ScoreEntry {
	if limit <= 0 {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.clock.Now()
	entries := make([]ScoreEntry, 0, limit)
	for key, item := range e.entries {
		if len(key) <= len(guildID)+1 || key[:len(guildID)+1] != guildID+":" {
			continue
		}
		if e.isExpired(item.lastUpdate, now) {
			delete(e.entries, key)
			continue
		}
		item.score = e.decay(item.score, item.lastUpdate, now)
		item.lastUpdate = now
		userID := key[len(guildID)+1:]
		entries = append(entries, ScoreEntry{UserID: userID, Score: item.score})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Score > entries[j].Score
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}
