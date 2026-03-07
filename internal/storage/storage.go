package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq" // Driver PostgreSQL obligatoire
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db *sql.DB
}

type GuildSettings struct {
	GuildID            string
	SecurityLogChannel string
	Language           string
	Mode               string
	RulePreset         string
	RetentionDays      int
	SpamMessages       int
	SpamWindowSeconds  int
	RaidJoins          int
	RaidWindowSeconds  int
	PhishingRisk       int
	LockdownEnabled    bool
	NukeEnabled        bool
	NukeWindowSeconds  int
	NukeChannelDelete  int
	NukeChannelCreate  int
	NukeChannelUpdate  int
	NukeRoleDelete     int
	NukeRoleCreate     int
	NukeRoleUpdate     int
	NukeWebhookUpdate  int
	NukeBanAdd         int
	NukeGuildUpdate    int
}

type AuditLog struct {
	ID        int64
	GuildID   string
	UserID    string
	Level     string
	Event     string
	Details   string
	CreatedAt time.Time
}

// New initialise la connexion à PostgreSQL
func New(connStr string) (*Store, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("erreur ouverture db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("impossible de joindre postgres: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS banned_users (
			guild_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			reason TEXT NOT NULL,
			created_at BIGINT NOT NULL,
			PRIMARY KEY (guild_id, user_id)
		)
	`); err != nil {
		return nil, fmt.Errorf("impossible de créer banned_users: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user_strikes (
			guild_id    TEXT NOT NULL,
			user_id     TEXT NOT NULL,
			strike_type TEXT NOT NULL,
			count       INTEGER NOT NULL DEFAULT 1,
			updated_at  BIGINT NOT NULL,
			PRIMARY KEY (guild_id, user_id, strike_type)
		)
	`); err != nil {
		return nil, fmt.Errorf("impossible de créer user_strikes: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

func (s *Store) Migrate() error {
	if s == nil || s.db == nil {
		return nil
	}
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at BIGINT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("failed to create schema_migrations: %w", err)
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migrations dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		version := entry.Name()

		var applied int
		row := s.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version = $1`, version)
		_ = row.Scan(&applied)
		if applied > 0 {
			continue
		}

		data, err := migrations.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", version, err)
		}

		if _, err := s.db.Exec(string(data)); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", version, err)
		}

		if _, err := s.db.Exec(
			`INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`,
			version, time.Now().Unix(),
		); err != nil {
			return fmt.Errorf("failed to record migration %s: %w", version, err)
		}
	}

	return nil
}

// --- Guild Settings ---

func (s *Store) GetGuildSettings(ctx context.Context, guildID string, defaults GuildSettings) (GuildSettings, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT security_log_channel, language, mode, rule_preset, retention_days,
		spam_messages, spam_window_seconds, raid_joins, raid_window_seconds,
		phishing_risk, lockdown_enabled,
		nuke_enabled, nuke_window_seconds, nuke_channel_delete, nuke_channel_create,
		nuke_channel_update, nuke_role_delete, nuke_role_create, nuke_role_update,
		nuke_webhook_update, nuke_ban_add, nuke_guild_update
		FROM guild_settings WHERE guild_id = $1`, guildID)

	result := defaults
	result.GuildID = guildID

	err := row.Scan(
		&result.SecurityLogChannel, &result.Language, &result.Mode, &result.RulePreset, &result.RetentionDays,
		&result.SpamMessages, &result.SpamWindowSeconds, &result.RaidJoins, &result.RaidWindowSeconds,
		&result.PhishingRisk, &result.LockdownEnabled, &result.NukeEnabled, &result.NukeWindowSeconds,
		&result.NukeChannelDelete, &result.NukeChannelCreate, &result.NukeChannelUpdate, &result.NukeRoleDelete,
		&result.NukeRoleCreate, &result.NukeRoleUpdate, &result.NukeWebhookUpdate, &result.NukeBanAdd,
		&result.NukeGuildUpdate,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, nil
		}
		return GuildSettings{}, err
	}
	return result, nil
}

func (s *Store) UpsertGuildSettings(ctx context.Context, settings GuildSettings) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO guild_settings (
			guild_id, security_log_channel, language, mode, rule_preset, retention_days,
			spam_messages, spam_window_seconds, raid_joins, raid_window_seconds,
			phishing_risk, lockdown_enabled,
			nuke_enabled, nuke_window_seconds, nuke_channel_delete, nuke_channel_create,
			nuke_channel_update, nuke_role_delete, nuke_role_create, nuke_role_update,
			nuke_webhook_update, nuke_ban_add, nuke_guild_update
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
		ON CONFLICT(guild_id) DO UPDATE SET
			security_log_channel = EXCLUDED.security_log_channel,
			language = EXCLUDED.language,
			mode = EXCLUDED.mode,
			rule_preset = EXCLUDED.rule_preset,
			retention_days = EXCLUDED.retention_days,
			spam_messages = EXCLUDED.spam_messages,
			spam_window_seconds = EXCLUDED.spam_window_seconds,
			raid_joins = EXCLUDED.raid_joins,
			raid_window_seconds = EXCLUDED.raid_window_seconds,
			phishing_risk = EXCLUDED.phishing_risk,
			lockdown_enabled = EXCLUDED.lockdown_enabled,
			nuke_enabled = EXCLUDED.nuke_enabled,
			nuke_window_seconds = EXCLUDED.nuke_window_seconds,
			nuke_channel_delete = EXCLUDED.nuke_channel_delete,
			nuke_channel_create = EXCLUDED.nuke_channel_create,
			nuke_channel_update = EXCLUDED.nuke_channel_update,
			nuke_role_delete = EXCLUDED.nuke_role_delete,
			nuke_role_create = EXCLUDED.nuke_role_create,
			nuke_role_update = EXCLUDED.nuke_role_update,
			nuke_webhook_update = EXCLUDED.nuke_webhook_update,
			nuke_ban_add = EXCLUDED.nuke_ban_add,
			nuke_guild_update = EXCLUDED.nuke_guild_update
	`,
		settings.GuildID, settings.SecurityLogChannel, settings.Language, settings.Mode, settings.RulePreset,
		settings.RetentionDays, settings.SpamMessages, settings.SpamWindowSeconds, settings.RaidJoins,
		settings.RaidWindowSeconds, settings.PhishingRisk, settings.LockdownEnabled,
		settings.NukeEnabled, settings.NukeWindowSeconds, settings.NukeChannelDelete,
		settings.NukeChannelCreate, settings.NukeChannelUpdate, settings.NukeRoleDelete,
		settings.NukeRoleCreate, settings.NukeRoleUpdate, settings.NukeWebhookUpdate,
		settings.NukeBanAdd, settings.NukeGuildUpdate,
	)
	return err
}

// --- Audit Logs ---

func (s *Store) AddAuditLog(ctx context.Context, log AuditLog) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (guild_id, user_id, level, event, details, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, log.GuildID, log.UserID, log.Level, log.Event, log.Details, log.CreatedAt.Unix())
	return err
}

func (s *Store) ListAuditLogs(ctx context.Context, guildID string, since time.Time) ([]AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, guild_id, user_id, level, event, details, created_at
		FROM audit_logs
		WHERE guild_id = $1 AND created_at >= $2
		ORDER BY created_at DESC
	`, guildID, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []AuditLog
	for rows.Next() {
		var log AuditLog
		var created int64
		if err := rows.Scan(&log.ID, &log.GuildID, &log.UserID, &log.Level, &log.Event, &log.Details, &created); err != nil {
			return nil, err
		}
		log.CreatedAt = time.Unix(created, 0)
		logs = append(logs, log)
	}
	return logs, rows.Err()
}

// --- Whitelist Users ---

func (s *Store) AddWhitelistUser(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO whitelist_users (guild_id, user_id, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, guildID, userID, time.Now().Unix())
	return err
}

func (s *Store) RemoveWhitelistUser(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM whitelist_users WHERE guild_id = $1 AND user_id = $2`, guildID, userID)
	return err
}

func (s *Store) ListWhitelistUsers(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id FROM whitelist_users WHERE guild_id = $1`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		users = append(users, id)
	}
	return users, nil
}

// --- Whitelist Roles ---

func (s *Store) AddWhitelistRole(ctx context.Context, guildID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO whitelist_roles (guild_id, role_id, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, guildID, roleID, time.Now().Unix())
	return err
}

func (s *Store) RemoveWhitelistRole(ctx context.Context, guildID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM whitelist_roles WHERE guild_id = $1 AND role_id = $2`, guildID, roleID)
	return err
}

func (s *Store) ListWhitelistRoles(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role_id FROM whitelist_roles WHERE guild_id = $1`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		roles = append(roles, id)
	}
	return roles, nil
}

// --- Domain Lists ---

func (s *Store) AddDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO domain_allowlist (guild_id, domain) VALUES ($1, $2) ON CONFLICT DO NOTHING`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) RemoveDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domain_allowlist WHERE guild_id = $1 AND domain = $2`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) ListDomainAllow(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_allowlist WHERE guild_id = $1`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		domains = append(domains, d)
	}
	return domains, nil
}

func (s *Store) AddDomainBlock(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO domain_blocklist (guild_id, domain) VALUES ($1, $2) ON CONFLICT DO NOTHING`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) RemoveDomainBlock(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domain_blocklist WHERE guild_id = $1 AND domain = $2`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) ListDomainBlock(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_blocklist WHERE guild_id = $1`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		domains = append(domains, d)
	}
	return domains, nil
}

func (s *Store) AddBannedUser(ctx context.Context, guildID, userID, reason string) error {
	if guildID == "" || userID == "" {
		return nil
	}
	if reason == "" {
		reason = "unspecified"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO banned_users (guild_id, user_id, reason, created_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (guild_id, user_id) DO UPDATE SET
			reason = EXCLUDED.reason,
			created_at = EXCLUDED.created_at
	`, guildID, userID, reason, time.Now().Unix())
	return err
}

func (s *Store) IsBannedUser(ctx context.Context, guildID, userID string) (bool, error) {
	if guildID == "" || userID == "" {
		return false, nil
	}
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM banned_users WHERE guild_id = $1 AND user_id = $2 LIMIT 1`, guildID, userID)
	var found int
	if err := row.Scan(&found); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return found == 1, nil
}

func (s *Store) GetBannedUserReason(ctx context.Context, guildID, userID string) (string, bool, error) {
	if guildID == "" || userID == "" {
		return "", false, nil
	}

	row := s.db.QueryRowContext(ctx, `SELECT reason FROM banned_users WHERE guild_id = $1 AND user_id = $2 LIMIT 1`, guildID, userID)
	var reason string
	if err := row.Scan(&reason); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}

	if strings.TrimSpace(reason) == "" {
		reason = "unspecified"
	}

	return reason, true, nil
}

func (s *Store) RemoveBannedUser(ctx context.Context, guildID, userID string) error {
	if guildID == "" || userID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM banned_users WHERE guild_id = $1 AND user_id = $2`, guildID, userID)
	return err
}

// --- User Strikes ---

// IncrementUserStrike atomically increments the strike counter for a user and returns the new count.
func (s *Store) IncrementUserStrike(ctx context.Context, guildID, userID, strikeType string) (int, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO user_strikes (guild_id, user_id, strike_type, count, updated_at)
		VALUES ($1, $2, $3, 1, $4)
		ON CONFLICT (guild_id, user_id, strike_type) DO UPDATE
		SET count = user_strikes.count + 1, updated_at = EXCLUDED.updated_at
		RETURNING count
	`, guildID, userID, strikeType, time.Now().Unix())
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetUserStrike returns the current strike count for a user (0 if none).
func (s *Store) GetUserStrike(ctx context.Context, guildID, userID, strikeType string) (int, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT count FROM user_strikes WHERE guild_id = $1 AND user_id = $2 AND strike_type = $3
	`, guildID, userID, strikeType)
	var count int
	if err := row.Scan(&count); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}
