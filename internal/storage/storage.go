package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq" // Driver PostgreSQL
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct {
	db *sql.DB
}

// ... Tes structures GuildSettings et AuditLog restent identiques ...
type GuildSettings struct {
	GuildID            string
	SecurityLogChannel string
	Language            string
	Mode                string
	RulePreset          string
	RetentionDays       int
	SpamMessages        int
	SpamWindowSeconds   int
	RaidJoins           int
	RaidWindowSeconds   int
	PhishingRisk        int
	LockdownEnabled     bool
	NukeEnabled         bool
	NukeWindowSeconds   int
	NukeChannelDelete   int
	NukeChannelCreate   int
	NukeChannelUpdate   int
	NukeRoleDelete      int
	NukeRoleCreate      int
	NukeRoleUpdate      int
	NukeWebhookUpdate   int
	NukeBanAdd          int
	NukeGuildUpdate     int
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

// New prend maintenant l'URL de connexion Postgres
func New(connStr string) (*Store, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

// Migrate est simplifié car tu as déjà fait le SQL manuellement
func (s *Store) Migrate() error {
	fmt.Println("Migration skip: Tables already created in pgAdmin")
	return nil
}

func (s *Store) GetGuildSettings(ctx context.Context, guildID string, defaults GuildSettings) (GuildSettings, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT security_log_channel, language, mode, rule_preset, retention_days,
		spam_messages, spam_window_seconds, raid_joins, raid_window_seconds,
		phishing_risk, lockdown_enabled,
		nuke_enabled, nuke_window_seconds, nuke_channel_delete, nuke_channel_create,
		nuke_channel_update, nuke_role_delete, nuke_role_create, nuke_role_update,
		nuke_webhook_update, nuke_ban_add, nuke_guild_update
		FROM guild_settings WHERE guild_id = $1`, guildID) // $1 au lieu de ?

	result := defaults
	result.GuildID = guildID

	var lockdown int
	var nukeEnabled int
	err := row.Scan(
		&result.SecurityLogChannel, &result.Language, &result.Mode, &result.RulePreset, &result.RetentionDays,
		&result.SpamMessages, &result.SpamWindowSeconds, &result.RaidJoins, &result.RaidWindowSeconds,
		&result.PhishingRisk, &lockdown, &nukeEnabled, &result.NukeWindowSeconds, &result.NukeChannelDelete,
		&result.NukeChannelCreate, &result.NukeChannelUpdate, &result.NukeRoleDelete, &result.NukeRoleCreate,
		&result.NukeRoleUpdate, &result.NukeWebhookUpdate, &result.NukeBanAdd, &result.NukeGuildUpdate,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) { return result, nil }
		return GuildSettings{}, err
	}
	result.LockdownEnabled = lockdown == 1
	result.NukeEnabled = nukeEnabled == 1
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
		settings.RaidWindowSeconds, settings.PhishingRisk, boolToInt(settings.LockdownEnabled),
		boolToInt(settings.NukeEnabled), settings.NukeWindowSeconds, settings.NukeChannelDelete,
		settings.NukeChannelCreate, settings.NukeChannelUpdate, settings.NukeRoleDelete,
		settings.NukeRoleCreate, settings.NukeRoleUpdate, settings.NukeWebhookUpdate,
		settings.NukeBanAdd, settings.NukeGuildUpdate,
	)
	return err
}

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
	if err != nil { return nil, err }
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

func (s *Store) CleanupAuditLogs(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, cutoff.Unix())
	return err
}

func (s *Store) AddDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO domain_allowlist (guild_id, domain) VALUES ($1, $2) ON CONFLICT DO NOTHING`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) RemoveDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domain_allowlist WHERE guild_id = $1 AND domain = $2`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) ListDomainAllow(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_allowlist WHERE guild_id = $1 ORDER BY domain`, guildID)
	if err != nil { return nil, err }
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil { return nil, err }
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

func (s *Store) AddWhitelistUser(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO whitelist_users (guild_id, user_id, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, guildID, userID, time.Now().Unix())
	return err
}

func (s *Store) RemoveWhitelistUser(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM whitelist_users WHERE guild_id = $1 AND user_id = $2`, guildID, userID)
	return err
}

func (s *Store) ListWhitelistUsers(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id FROM whitelist_users WHERE guild_id = $1 ORDER BY user_id`, guildID)
	if err != nil { return nil, err }
	defer rows.Close()

	var users []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil { return nil, err }
		users = append(users, userID)
	}
	return users, rows.Err()
}

func (s *Store) AddWhitelistRole(ctx context.Context, guildID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO whitelist_roles (guild_id, role_id, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, guildID, roleID, time.Now().Unix())
	return err
}

func (s *Store) RemoveWhitelistRole(ctx context.Context, guildID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM whitelist_roles WHERE guild_id = $1 AND role_id = $2`, guildID, roleID)
	return err
}

func (s *Store) ListWhitelistRoles(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role_id FROM whitelist_roles WHERE guild_id = $1 ORDER BY role_id`, guildID)
	if err != nil { return nil, err }
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil { return nil, err }
		roles = append(roles, roleID)
	}
	return roles, rows.Err()
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
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_blocklist WHERE guild_id = $1 ORDER BY domain`, guildID)
	if err != nil { return nil, err }
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil { return nil, err }
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

func boolToInt(value bool) int {
	if value { return 1 }
	return 0
}

func isIgnorableMigrationError(err error) bool {
	if err == nil { return false }
	message := err.Error()
	return strings.Contains(message, "duplicate column name") || strings.Contains(message, "already exists")
}
