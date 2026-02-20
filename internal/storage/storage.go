package storage

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
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

func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
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

func (s *Store) Migrate() error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}

	var files []string
	for _, entry := range entries {
		files = append(files, entry.Name())
	}
	sort.Strings(files)

	for _, file := range files {
		content, err := migrations.ReadFile(path.Join("migrations", file))
		if err != nil {
			return err
		}
		if _, err := s.db.Exec(string(content)); err != nil {
			if isIgnorableMigrationError(err) {
				continue
			}
			return fmt.Errorf("migration %s failed: %w", file, err)
		}
	}
	return nil
}

func (s *Store) GetGuildSettings(ctx context.Context, guildID string, defaults GuildSettings) (GuildSettings, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT security_log_channel, language, mode, rule_preset, retention_days,
		spam_messages, spam_window_seconds, raid_joins, raid_window_seconds,
		phishing_risk, lockdown_enabled
		FROM guild_settings WHERE guild_id = ?`, guildID)

	result := defaults
	result.GuildID = guildID

	var lockdown int
	err := row.Scan(
		&result.SecurityLogChannel,
		&result.Language,
		&result.Mode,
		&result.RulePreset,
		&result.RetentionDays,
		&result.SpamMessages,
		&result.SpamWindowSeconds,
		&result.RaidJoins,
		&result.RaidWindowSeconds,
		&result.PhishingRisk,
		&lockdown,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, nil
		}
		return GuildSettings{}, err
	}
	result.LockdownEnabled = lockdown == 1
	if result.Language == "" {
		result.Language = defaults.Language
	}
	return result, nil
}

func (s *Store) UpsertGuildSettings(ctx context.Context, settings GuildSettings) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO guild_settings (
			guild_id, security_log_channel, language, mode, rule_preset, retention_days,
			spam_messages, spam_window_seconds, raid_joins, raid_window_seconds,
			phishing_risk, lockdown_enabled
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(guild_id) DO UPDATE SET
			security_log_channel = excluded.security_log_channel,
			language = excluded.language,
			mode = excluded.mode,
			rule_preset = excluded.rule_preset,
			retention_days = excluded.retention_days,
			spam_messages = excluded.spam_messages,
			spam_window_seconds = excluded.spam_window_seconds,
			raid_joins = excluded.raid_joins,
			raid_window_seconds = excluded.raid_window_seconds,
			phishing_risk = excluded.phishing_risk,
			lockdown_enabled = excluded.lockdown_enabled
	`,
		settings.GuildID,
		settings.SecurityLogChannel,
		settings.Language,
		settings.Mode,
		settings.RulePreset,
		settings.RetentionDays,
		settings.SpamMessages,
		settings.SpamWindowSeconds,
		settings.RaidJoins,
		settings.RaidWindowSeconds,
		settings.PhishingRisk,
		boolToInt(settings.LockdownEnabled),
	)
	return err
}

func (s *Store) AddAuditLog(ctx context.Context, log AuditLog) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (guild_id, user_id, level, event, details, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, log.GuildID, log.UserID, log.Level, log.Event, log.Details, log.CreatedAt.Unix())
	return err
}

func (s *Store) ListAuditLogs(ctx context.Context, guildID string, since time.Time) ([]AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, guild_id, user_id, level, event, details, created_at
		FROM audit_logs
		WHERE guild_id = ? AND created_at >= ?
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

func (s *Store) CleanupAuditLogs(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE created_at < ?`, cutoff.Unix())
	return err
}

func (s *Store) AddDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO domain_allowlist (guild_id, domain) VALUES (?, ?)`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) RemoveDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domain_allowlist WHERE guild_id = ? AND domain = ?`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) ListDomainAllow(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_allowlist WHERE guild_id = ? ORDER BY domain`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

func (s *Store) AddDomainBlock(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO domain_blocklist (guild_id, domain) VALUES (?, ?)`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) RemoveDomainBlock(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domain_blocklist WHERE guild_id = ? AND domain = ?`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) ListDomainBlock(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_blocklist WHERE guild_id = ? ORDER BY domain`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, rows.Err()
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func isIgnorableMigrationError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "duplicate column name") || strings.Contains(message, "already exists")
}
