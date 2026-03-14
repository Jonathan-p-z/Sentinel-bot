package antinuke

import (
	"testing"
	"time"
)

func TestCountPerAction(t *testing.T) {
	module := New(10 * time.Second)

	if count := module.Count("g1", "u1", "channel_delete"); count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}
	if count := module.Count("g1", "u1", "channel_delete"); count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
}

func TestCountAnyAcrossActions(t *testing.T) {
	module := New(10 * time.Second)

	_ = module.Count("g1", "u1", "channel_delete")
	if total := module.CountAny("g1", "u1"); total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}

	_ = module.Count("g1", "u1", "role_delete")
	if total := module.CountAny("g1", "u1"); total != 2 {
		t.Fatalf("expected total 2 after mixed actions, got %d", total)
	}
}
