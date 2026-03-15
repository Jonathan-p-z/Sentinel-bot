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

	_ "github.com/jackc/pgx/v5/stdlib"
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

type WebUser struct {
	UserID        string
	Username      string
	Discriminator string
	Avatar        string
	Email         string
	GuildsJSON    string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type WebSession struct {
	Token     string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Subscription struct {
	ID                   int64
	UserID               string
	GuildID              string
	Plan                 string
	StripeCustomerID     string
	StripeSubscriptionID string
	Status               string
	CurrentPeriodEnd     time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func New(databaseURL string) (*Store, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
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
		for _, stmt := range splitStatements(string(content)) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := s.db.Exec(stmt); err != nil {
				if isIgnorableMigrationError(err) {
					continue
				}
				return fmt.Errorf("migration %s failed: %w", file, err)
			}
		}
	}
	return nil
}

func splitStatements(sql string) []string {
	return strings.Split(sql, ";")
}

// ── Guild settings ────────────────────────────────────────────────────────────

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
		&result.LockdownEnabled,
		&result.NukeEnabled,
		&result.NukeWindowSeconds,
		&result.NukeChannelDelete,
		&result.NukeChannelCreate,
		&result.NukeChannelUpdate,
		&result.NukeRoleDelete,
		&result.NukeRoleCreate,
		&result.NukeRoleUpdate,
		&result.NukeWebhookUpdate,
		&result.NukeBanAdd,
		&result.NukeGuildUpdate,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, nil
		}
		return GuildSettings{}, err
	}
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
			phishing_risk, lockdown_enabled,
			nuke_enabled, nuke_window_seconds, nuke_channel_delete, nuke_channel_create,
			nuke_channel_update, nuke_role_delete, nuke_role_create, nuke_role_update,
			nuke_webhook_update, nuke_ban_add, nuke_guild_update
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
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
			nuke_guild_update = EXCLUDED.nuke_guild_update`,
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
		settings.LockdownEnabled,
		settings.NukeEnabled,
		settings.NukeWindowSeconds,
		settings.NukeChannelDelete,
		settings.NukeChannelCreate,
		settings.NukeChannelUpdate,
		settings.NukeRoleDelete,
		settings.NukeRoleCreate,
		settings.NukeRoleUpdate,
		settings.NukeWebhookUpdate,
		settings.NukeBanAdd,
		settings.NukeGuildUpdate,
	)
	return err
}

// ── Audit logs ────────────────────────────────────────────────────────────────

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
		var l AuditLog
		var created int64
		if err := rows.Scan(&l.ID, &l.GuildID, &l.UserID, &l.Level, &l.Event, &l.Details, &created); err != nil {
			return nil, err
		}
		l.CreatedAt = time.Unix(created, 0)
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

func (s *Store) CleanupAuditLogs(ctx context.Context, retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_, err := s.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, cutoff.Unix())
	return err
}

// ── Domain allow/block lists ──────────────────────────────────────────────────

func (s *Store) AddDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO domain_allowlist (guild_id, domain) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) RemoveDomainAllow(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domain_allowlist WHERE guild_id = $1 AND domain = $2`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) ListDomainAllow(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_allowlist WHERE guild_id = $1 ORDER BY domain`, guildID)
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
	return domains, rows.Err()
}

func (s *Store) AddDomainBlock(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO domain_blocklist (guild_id, domain) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) RemoveDomainBlock(ctx context.Context, guildID, domain string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM domain_blocklist WHERE guild_id = $1 AND domain = $2`, guildID, strings.ToLower(domain))
	return err
}

func (s *Store) ListDomainBlock(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM domain_blocklist WHERE guild_id = $1 ORDER BY domain`, guildID)
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
	return domains, rows.Err()
}

// ── Whitelists ────────────────────────────────────────────────────────────────

func (s *Store) AddWhitelistUser(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO whitelist_users (guild_id, user_id, created_at) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, guildID, userID, time.Now().Unix())
	return err
}

func (s *Store) RemoveWhitelistUser(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM whitelist_users WHERE guild_id = $1 AND user_id = $2`, guildID, userID)
	return err
}

func (s *Store) ListWhitelistUsers(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id FROM whitelist_users WHERE guild_id = $1 ORDER BY user_id`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) AddWhitelistRole(ctx context.Context, guildID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO whitelist_roles (guild_id, role_id, created_at) VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING`, guildID, roleID, time.Now().Unix())
	return err
}

func (s *Store) RemoveWhitelistRole(ctx context.Context, guildID, roleID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM whitelist_roles WHERE guild_id = $1 AND role_id = $2`, guildID, roleID)
	return err
}

func (s *Store) ListWhitelistRoles(ctx context.Context, guildID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role_id FROM whitelist_roles WHERE guild_id = $1 ORDER BY role_id`, guildID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// ── Web users ─────────────────────────────────────────────────────────────────

func (s *Store) UpsertWebUser(ctx context.Context, u WebUser) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO discord_users (user_id, username, discriminator, avatar, email, guilds_json, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT(user_id) DO UPDATE SET
			username = EXCLUDED.username,
			discriminator = EXCLUDED.discriminator,
			avatar = EXCLUDED.avatar,
			email = EXCLUDED.email,
			guilds_json = EXCLUDED.guilds_json,
			updated_at = EXCLUDED.updated_at`,
		u.UserID, u.Username, u.Discriminator, u.Avatar, u.Email, u.GuildsJSON,
		u.CreatedAt.Unix(), u.UpdatedAt.Unix())
	return err
}

func (s *Store) GetWebUser(ctx context.Context, userID string) (*WebUser, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT user_id, username, discriminator, avatar, email, guilds_json, created_at, updated_at
		FROM discord_users WHERE user_id = $1`, userID)
	var u WebUser
	var createdAt, updatedAt int64
	err := row.Scan(&u.UserID, &u.Username, &u.Discriminator, &u.Avatar, &u.Email, &u.GuildsJSON, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.CreatedAt = time.Unix(createdAt, 0)
	u.UpdatedAt = time.Unix(updatedAt, 0)
	return &u, nil
}

// ── Web sessions ──────────────────────────────────────────────────────────────

func (s *Store) CreateSession(ctx context.Context, sess WebSession) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO web_sessions (token, user_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4)`,
		sess.Token, sess.UserID, sess.ExpiresAt.Unix(), sess.CreatedAt.Unix())
	return err
}

func (s *Store) GetSession(ctx context.Context, token string) (*WebSession, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token, user_id, expires_at, created_at
		FROM web_sessions WHERE token = $1 AND expires_at > $2`,
		token, time.Now().Unix())
	var sess WebSession
	var expiresAt, createdAt int64
	err := row.Scan(&sess.Token, &sess.UserID, &expiresAt, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	sess.ExpiresAt = time.Unix(expiresAt, 0)
	sess.CreatedAt = time.Unix(createdAt, 0)
	return &sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE token = $1`, token)
	return err
}

func (s *Store) CleanupSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at < $1`, time.Now().Unix())
	return err
}

// ── Subscriptions ─────────────────────────────────────────────────────────────

func (s *Store) UpsertSubscription(ctx context.Context, sub Subscription) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO subscriptions (user_id, guild_id, plan, stripe_customer_id, stripe_subscription_id, status, current_period_end, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT(guild_id) DO UPDATE SET
			user_id = EXCLUDED.user_id,
			plan = EXCLUDED.plan,
			stripe_customer_id = EXCLUDED.stripe_customer_id,
			stripe_subscription_id = EXCLUDED.stripe_subscription_id,
			status = EXCLUDED.status,
			current_period_end = EXCLUDED.current_period_end,
			updated_at = EXCLUDED.updated_at`,
		sub.UserID, sub.GuildID, sub.Plan,
		sub.StripeCustomerID, sub.StripeSubscriptionID,
		sub.Status, sub.CurrentPeriodEnd.Unix(),
		sub.CreatedAt.Unix(), sub.UpdatedAt.Unix())
	return err
}

func (s *Store) GetSubscription(ctx context.Context, guildID string) (*Subscription, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, guild_id, plan, stripe_customer_id, stripe_subscription_id, status, current_period_end, created_at, updated_at
		FROM subscriptions WHERE guild_id = $1`, guildID)
	var sub Subscription
	var periodEnd, createdAt, updatedAt int64
	err := row.Scan(&sub.ID, &sub.UserID, &sub.GuildID, &sub.Plan,
		&sub.StripeCustomerID, &sub.StripeSubscriptionID,
		&sub.Status, &periodEnd, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	sub.CurrentPeriodEnd = time.Unix(periodEnd, 0)
	sub.CreatedAt = time.Unix(createdAt, 0)
	sub.UpdatedAt = time.Unix(updatedAt, 0)
	return &sub, nil
}

func (s *Store) ListUserSubscriptions(ctx context.Context, userID string) ([]Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, guild_id, plan, stripe_customer_id, stripe_subscription_id, status, current_period_end, created_at, updated_at
		FROM subscriptions WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subs []Subscription
	for rows.Next() {
		var sub Subscription
		var periodEnd, createdAt, updatedAt int64
		if err := rows.Scan(&sub.ID, &sub.UserID, &sub.GuildID, &sub.Plan,
			&sub.StripeCustomerID, &sub.StripeSubscriptionID,
			&sub.Status, &periodEnd, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		sub.CurrentPeriodEnd = time.Unix(periodEnd, 0)
		sub.CreatedAt = time.Unix(createdAt, 0)
		sub.UpdatedAt = time.Unix(updatedAt, 0)
		subs = append(subs, sub)
	}
	return subs, rows.Err()
}

// ── Admin stats ───────────────────────────────────────────────────────────────

func (s *Store) CountGuildSettings(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM guild_settings`).Scan(&n)
	return n, err
}

func (s *Store) CountSubscriptionsByPlan(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT plan, COUNT(*) FROM subscriptions WHERE status = 'active' GROUP BY plan`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int{"free": 0, "pro": 0, "business": 0, "enterprise": 0}
	for rows.Next() {
		var plan string
		var count int
		if err := rows.Scan(&plan, &count); err != nil {
			return nil, err
		}
		result[plan] = count
	}
	return result, rows.Err()
}

// ── Escalation log ────────────────────────────────────────────────────────────

func (s *Store) AddEscalationLog(ctx context.Context, guildID, userID, action string, score float64) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO escalation_log (guild_id, user_id, action, score, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		guildID, userID, action, score, time.Now().Unix())
	return err
}

func (s *Store) GetLastEscalation(ctx context.Context, guildID, userID string) (time.Time, bool, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT created_at FROM escalation_log
		WHERE guild_id = $1 AND user_id = $2
		ORDER BY created_at DESC LIMIT 1`,
		guildID, userID)
	var ts int64
	err := row.Scan(&ts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, false, nil
		}
		return time.Time{}, false, err
	}
	return time.Unix(ts, 0), true, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isIgnorableMigrationError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate column name")
}
