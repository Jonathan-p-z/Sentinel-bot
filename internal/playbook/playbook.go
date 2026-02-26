package playbook

import (
	"context"
	"sync"
	"time"

	"sentinel-adaptive/internal/modules/audit"
)

type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) Timer
}

type Timer interface {
	Stop() bool
}

type realClock struct{}

type realTimer struct{ t *time.Timer }

func (realClock) Now() time.Time { return time.Now() }

func (realClock) AfterFunc(d time.Duration, f func()) Timer {
	return realTimer{t: time.AfterFunc(d, f)}
}

func (t realTimer) Stop() bool { return t.t.Stop() }

type Config struct {
	LockdownMinutes   int
	StrictModeMinutes int
	ExitStepSeconds   int
}

type State struct {
	Lockdown bool
	Strict   bool
	Exiting  bool
}

type Engine struct {
	mu     sync.RWMutex
	cfg    Config
	clock  Clock
	audit  *audit.Logger
	states map[string]*State
}

func New(cfg Config, auditLogger *audit.Logger) *Engine {
	return &Engine{
		cfg:    cfg,
		clock:  realClock{},
		audit:  auditLogger,
		states: make(map[string]*State),
	}
}

func (e *Engine) WithClock(clock Clock) {
	e.clock = clock
}

func (e *Engine) TriggerLockdown(ctx context.Context, guildID string) bool {
	e.mu.Lock()
	state := e.stateLocked(guildID)
	if state.Lockdown {
		e.mu.Unlock()
		return false
	}

	state.Lockdown = true
	state.Strict = true
	state.Exiting = false
	e.mu.Unlock()

	e.audit.Log(ctx, audit.LevelWarn, guildID, "", "raid_lockdown", "lockdown initiated")
	e.scheduleExit(ctx, guildID)
	return true
}

func (e *Engine) IsLockdown(guildID string) State {
	e.mu.RLock()
	defer e.mu.RUnlock()
	state := e.states[guildID]
	if state == nil {
		return State{}
	}
	return *state
}

func (e *Engine) scheduleExit(ctx context.Context, guildID string) {
	strictDuration := time.Duration(e.cfg.StrictModeMinutes) * time.Minute
	lockdownDuration := time.Duration(e.cfg.LockdownMinutes) * time.Minute
	if strictDuration <= 0 {
		strictDuration = 5 * time.Minute
	}
	if lockdownDuration <= 0 {
		lockdownDuration = 10 * time.Minute
	}

	e.clock.AfterFunc(strictDuration, func() {
		e.mu.Lock()
		state := e.stateLocked(guildID)
		state.Strict = false
		state.Exiting = true
		e.mu.Unlock()
		e.audit.Log(ctx, audit.LevelInfo, guildID, "", "raid_lockdown", "strict mode exit started")
	})

	e.clock.AfterFunc(lockdownDuration, func() {
		e.mu.Lock()
		state := e.stateLocked(guildID)
		state.Lockdown = false
		state.Strict = false
		state.Exiting = false
		e.mu.Unlock()
		e.audit.Log(ctx, audit.LevelInfo, guildID, "", "raid_lockdown", "lockdown ended")
	})
}

func (e *Engine) stateLocked(guildID string) *State {
	state := e.states[guildID]
	if state == nil {
		state = &State{}
		e.states[guildID] = state
	}
	return state
}
