package trust

import (
	"math"
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
	cfg     config.TrustConfig
	clock   Clock
	entries map[string]*entry
}

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func NewEngine(cfg config.TrustConfig) *Engine {
	return &Engine{
		cfg:     cfg,
		clock:   realClock{},
		entries: make(map[string]*entry),
	}
}

func (e *Engine) WithClock(clock Clock) {
	e.clock = clock
}

func (e *Engine) Increase(guildID, userID string, delta float64) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := guildID + ":" + userID
	now := e.clock.Now()

	item := e.entries[key]
	if item == nil {
		item = &entry{score: 0, lastUpdate: now}
		e.entries[key] = item
	}

	item.score = math.Min(e.cfg.MaxScore, item.score+delta)
	item.lastUpdate = now
	return item.score
}

func (e *Engine) Decrease(guildID, userID string, delta float64) float64 {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := guildID + ":" + userID
	now := e.clock.Now()

	item := e.entries[key]
	if item == nil {
		item = &entry{score: 0, lastUpdate: now}
		e.entries[key] = item
	}

	item.score = math.Max(0, item.score-delta)
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

	item.lastUpdate = now
	return item.score
}

func (e *Engine) isExpired(lastUpdate, now time.Time) bool {
	if e.cfg.TTLMinutes <= 0 {
		return false
	}
	return now.Sub(lastUpdate) > (time.Duration(e.cfg.TTLMinutes) * time.Minute)
}
