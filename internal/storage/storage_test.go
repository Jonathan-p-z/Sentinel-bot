package storage

import (
	"context"
	"os"
	"testing"
)

func TestUpsertGuildSettings(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN non défini; test d'intégration PostgreSQL ignoré")
	}

	store, err := New(dsn)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	if _, err := store.db.Exec(`
		CREATE TABLE IF NOT EXISTS guild_settings (
			guild_id TEXT PRIMARY KEY,
			security_log_channel TEXT NOT NULL DEFAULT '',
			language TEXT NOT NULL DEFAULT 'fr',
			mode TEXT NOT NULL DEFAULT 'normal',
			rule_preset TEXT NOT NULL DEFAULT 'medium',
			retention_days INT NOT NULL DEFAULT 30,
			spam_messages INT NOT NULL DEFAULT 7,
			spam_window_seconds INT NOT NULL DEFAULT 10,
			raid_joins INT NOT NULL DEFAULT 8,
			raid_window_seconds INT NOT NULL DEFAULT 15,
			phishing_risk INT NOT NULL DEFAULT 20,
			lockdown_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			nuke_enabled BOOLEAN NOT NULL DEFAULT TRUE,
			nuke_window_seconds INT NOT NULL DEFAULT 20,
			nuke_channel_delete INT NOT NULL DEFAULT 3,
			nuke_channel_create INT NOT NULL DEFAULT 6,
			nuke_channel_update INT NOT NULL DEFAULT 6,
			nuke_role_delete INT NOT NULL DEFAULT 3,
			nuke_role_create INT NOT NULL DEFAULT 6,
			nuke_role_update INT NOT NULL DEFAULT 6,
			nuke_webhook_update INT NOT NULL DEFAULT 4,
			nuke_ban_add INT NOT NULL DEFAULT 3,
			nuke_guild_update INT NOT NULL DEFAULT 2
		)
	`); err != nil {
		t.Fatalf("create guild_settings table: %v", err)
	}

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
