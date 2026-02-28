package storage

import (
	"context"
	"testing"
)

func TestUpsertGuildSettings(t *testing.T) {
	store, err := New(":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	settings := GuildSettings{
		GuildID:            "g1",
		SecurityLogChannel: "c1",
		Language:           "fr",
		Mode:               "normal",
		RulePreset:         "medium",
		RetentionDays:      30,
		SpamMessages:       7,
		SpamWindowSeconds:  10,
		RaidJoins:          8,
		RaidWindowSeconds:  15,
		PhishingRisk:       20,
		LockdownEnabled:    false,
		NukeEnabled:        true,
		NukeWindowSeconds:  20,
		NukeChannelDelete:  3,
		NukeChannelCreate:  6,
		NukeChannelUpdate:  6,
		NukeRoleDelete:     3,
		NukeRoleCreate:     6,
		NukeRoleUpdate:     6,
		NukeWebhookUpdate:  4,
		NukeBanAdd:         3,
		NukeGuildUpdate:    2,
	}

	if err := store.UpsertGuildSettings(context.Background(), settings); err != nil {
		t.Fatalf("upsert guild settings: %v", err)
	}

	settings.SecurityLogChannel = "c2"
	if err := store.UpsertGuildSettings(context.Background(), settings); err != nil {
		t.Fatalf("update guild settings: %v", err)
	}

	got, err := store.GetGuildSettings(context.Background(), "g1", GuildSettings{})
	if err != nil {
		t.Fatalf("get guild settings: %v", err)
	}
	if got.SecurityLogChannel != "c2" {
		t.Fatalf("expected channel c2, got %q", got.SecurityLogChannel)
	}
}
