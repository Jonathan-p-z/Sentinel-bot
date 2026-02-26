package trust

import (
	"testing"
	"time"

	"sentinel-adaptive/internal/config"
)

type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

func TestTrustTTL(t *testing.T) {
	cfg := config.TrustConfig{MaxScore: 100, TTLMinutes: 1}
	engine := NewEngine(cfg)
	engine.WithClock(fakeClock{now: time.Unix(0, 0)})

	engine.Increase("g1", "u1", 10)
	engine.WithClock(fakeClock{now: time.Unix(0, 0).Add(2 * time.Minute)})
	if score := engine.GetScore("g1", "u1"); score != 0 {
		t.Fatalf("expected 0, got %f", score)
	}
}
