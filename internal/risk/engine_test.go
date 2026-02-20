package risk

import (
	"testing"
	"time"

	"sentinel-adaptive/internal/config"
)

type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

func TestRiskDecayAndTrust(t *testing.T) {
	rCfg := config.RiskConfig{DecayPerMinute: 1, TTLMinutes: 60, TrustWeight: 0.5}
	engine := NewEngine(rCfg)
	engine.WithClock(fakeClock{now: time.Unix(0, 0)})

	score := engine.AddRisk("g1", "u1", 10)
	if score != 10 {
		t.Fatalf("expected 10, got %f", score)
	}

	engine.WithClock(fakeClock{now: time.Unix(0, 0).Add(3 * time.Minute)})
	score = engine.GetScore("g1", "u1")
	if score != 7 {
		t.Fatalf("expected 7, got %f", score)
	}

	effective := engine.EffectiveScore(score, 6)
	if effective != 4 {
		t.Fatalf("expected 4, got %f", effective)
	}
}
