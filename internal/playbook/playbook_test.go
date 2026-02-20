package playbook

import (
	"context"
	"sync"
	"testing"
	"time"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/storage"

	"go.uber.org/zap"
)

type fakeTimer struct {
	stop bool
	fn   func()
}

func (t *fakeTimer) Stop() bool {
	t.stop = true
	return true
}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
	delays []time.Duration
}

func (f *fakeClock) Now() time.Time { return f.now }

func (f *fakeClock) AfterFunc(d time.Duration, fn func()) Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTimer{fn: fn}
	f.timers = append(f.timers, t)
	f.delays = append(f.delays, d)
	return t
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	pending := append([]*fakeTimer{}, f.timers...)
	f.timers = nil
	f.delays = nil
	f.mu.Unlock()
	for _, timer := range pending {
		timer.fn()
	}
}

func TestPlaybookTrigger(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	logger := zap.NewNop()
	auditLogger := audit.NewLogger(store, logger)

	engine := New(Config{LockdownMinutes: 1, StrictModeMinutes: 1, ExitStepSeconds: 1}, auditLogger)
	clock := &fakeClock{now: time.Unix(0, 0)}
	engine.WithClock(clock)

	ctx := context.Background()
	if !engine.TriggerLockdown(ctx, "g1") {
		t.Fatalf("expected trigger")
	}
	state := engine.IsLockdown("g1")
	if !state.Lockdown || !state.Strict {
		t.Fatalf("expected lockdown strict")
	}

	clock.Advance(2 * time.Minute)
	state = engine.IsLockdown("g1")
	if state.Lockdown {
		t.Fatalf("expected lockdown ended")
	}
}
