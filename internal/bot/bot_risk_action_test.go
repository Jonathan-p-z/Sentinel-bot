package bot

import "testing"

func TestShouldSuppressRiskAction(t *testing.T) {
	b := &Bot{
		riskActionAgg: make(map[string]*riskActionAggregate),
	}

	if suppressed := b.shouldSuppressRiskAction("g1", "u1", "ban", false); suppressed {
		t.Fatalf("first action should not be suppressed")
	}
	if suppressed := b.shouldSuppressRiskAction("g1", "u1", "ban", false); !suppressed {
		t.Fatalf("second immediate action should be suppressed")
	}
}

func TestShouldSuppressRiskActionSeparatesAuditMode(t *testing.T) {
	b := &Bot{
		riskActionAgg: make(map[string]*riskActionAggregate),
	}

	if suppressed := b.shouldSuppressRiskAction("g1", "u1", "ban", false); suppressed {
		t.Fatalf("normal mode first action should not be suppressed")
	}
	if suppressed := b.shouldSuppressRiskAction("g1", "u1", "ban", true); suppressed {
		t.Fatalf("audit mode should use separate suppression key")
	}
}

func TestAntiHateSanctionForStrike(t *testing.T) {
	tests := []struct {
		name           string
		strike         int
		wantAction     string
		wantTimeoutMin int
	}{
		{name: "first offense warns", strike: 1, wantAction: "warn", wantTimeoutMin: 0},
		{name: "second offense timeout 5", strike: 2, wantAction: "timeout", wantTimeoutMin: 5},
		{name: "third offense timeout 15", strike: 3, wantAction: "timeout", wantTimeoutMin: 15},
		{name: "fifth offense timeout 60", strike: 5, wantAction: "timeout", wantTimeoutMin: 60},
		{name: "sixth offense bans", strike: 6, wantAction: "ban", wantTimeoutMin: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := antiHateSanctionForStrike(tt.strike)
			if got.action != tt.wantAction {
				t.Fatalf("action = %q, want %q", got.action, tt.wantAction)
			}
			if got.timeoutMinutes != tt.wantTimeoutMin {
				t.Fatalf("timeoutMinutes = %d, want %d", got.timeoutMinutes, tt.wantTimeoutMin)
			}
		})
	}
}

func TestAntiHateProgressText(t *testing.T) {
	tests := []struct {
		name   string
		strike int
		want   string
	}{
		{name: "first strike shows four timeouts left", strike: 1, want: "Infraction 1: il te reste 4 timeouts avant le ban definitif."},
		{name: "second strike shows three timeouts left", strike: 2, want: "Infraction 2: il te reste 3 timeouts avant le ban definitif."},
		{name: "fifth strike shows last chance", strike: 5, want: "Infraction 5: il te reste 1 seule chance avant le ban definitif."},
		{name: "sixth strike shows ban applied", strike: 6, want: "Infraction 6: ban definitif applique."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := antiHateProgressText("fr", tt.strike)
			if got != tt.want {
				t.Fatalf("progress = %q, want %q", got, tt.want)
			}
		})
	}
}
