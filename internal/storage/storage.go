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

//go:embed migrations
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

	// Auto-provisioned per-guild IDs.
	OnboardingRoleID       string
	ShadowmuteLogChannelID string

	TicketCategoryID string
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

func (s *Store) ensureMigrationsTable() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT   PRIMARY KEY,
			applied_at BIGINT NOT NULL
		)`)
	return err
}

func (s *Store) appliedVersionSet() (map[string]struct{}, error) {
	rows, err := s.db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := make(map[string]struct{})
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = struct{}{}
	}
	return applied, rows.Err()
}

func (s *Store) lastAppliedVersions(n int) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT version FROM schema_migrations
		ORDER BY applied_at DESC, version DESC
		LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// Migrate is a backward-compatible alias for MigrateUp.
func (s *Store) Migrate() error {
	return s.MigrateUp()
}

// MigrateUp applies all pending *.up.sql migrations in version order.
// It records each applied migration in schema_migrations to avoid re-runs.
func (s *Store) MigrateUp() error {
	if err := s.ensureMigrationsTable(); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}
	applied, err := s.appliedVersionSet()
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}

	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}

	var upFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	for _, file := range upFiles {
		version := migrationVersion(file)
		if _, ok := applied[version]; ok {
			continue // already applied
		}
		if err := s.execMigrationFile(file); err != nil {
			return err
		}
		if _, err := s.db.Exec(
			`INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)`,
			version, time.Now().Unix(),
		); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	return nil
}

// MigrateDown rolls back the last `steps` applied migrations using *.down.sql files.
func (s *Store) MigrateDown(steps int) error {
	if steps <= 0 {
		steps = 1
	}
	if err := s.ensureMigrationsTable(); err != nil {
		return fmt.Errorf("ensure migrations table: %w", err)
	}
	toRollback, err := s.lastAppliedVersions(steps)
	if err != nil {
		return fmt.Errorf("read applied migrations: %w", err)
	}
	for _, version := range toRollback {
		file := version + ".down.sql"
		if err := s.execMigrationFile(file); err != nil {
			return err
		}
		if _, err := s.db.Exec(
			`DELETE FROM schema_migrations WHERE version = $1`, version,
		); err != nil {
			return fmt.Errorf("remove migration record %s: %w", version, err)
		}
	}
	return nil
}

func (s *Store) execMigrationFile(filename string) error {
	content, err := migrations.ReadFile(path.Join("migrations", filename))
	if err != nil {
		return fmt.Errorf("read migration file %s: %w", filename, err)
	}
	for _, stmt := range splitStatements(string(content)) {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || isCommentOnly(stmt) {
			continue
		}
		if _, err := s.db.Exec(stmt); err != nil {
			if isIgnorableMigrationError(err) {
				continue
			}
			return fmt.Errorf("migration %s failed: %w", filename, err)
		}
	}
	return nil
}

func migrationVersion(filename string) string {
	v := strings.TrimSuffix(filename, ".sql")
	v = strings.TrimSuffix(v, ".up")
	v = strings.TrimSuffix(v, ".down")
	return v
}

func isCommentOnly(stmt string) bool {
	for _, line := range strings.Split(stmt, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		return false
	}
	return true
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
		nuke_webhook_update, nuke_ban_add, nuke_guild_update,
		onboarding_role_id, shadowmute_log_channel_id, ticket_category_id
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
		&result.OnboardingRoleID,
		&result.ShadowmuteLogChannelID,
		&result.TicketCategoryID,
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
			nuke_webhook_update, nuke_ban_add, nuke_guild_update,
			onboarding_role_id, shadowmute_log_channel_id, ticket_category_id
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
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
			nuke_guild_update = EXCLUDED.nuke_guild_update,
			onboarding_role_id = EXCLUDED.onboarding_role_id,
			shadowmute_log_channel_id = EXCLUDED.shadowmute_log_channel_id,
			ticket_category_id = EXCLUDED.ticket_category_id`,
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
		settings.OnboardingRoleID,
		settings.ShadowmuteLogChannelID,
		settings.TicketCategoryID,
	)
	return err
}

func (s *Store) SetTicketCategoryID(ctx context.Context, guildID, categoryID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO guild_settings (guild_id, ticket_category_id)
		VALUES ($1, $2)
		ON CONFLICT(guild_id) DO UPDATE SET ticket_category_id = EXCLUDED.ticket_category_id`,
		guildID, categoryID)
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

// ── Alt-account tables ────────────────────────────────────────────────────────

type JoinLogEntry struct {
	GuildID  string
	UserID   string
	Username string
	JoinedAt time.Time
}

type BannedUserEntry struct {
	GuildID  string
	UserID   string
	Username string
	BannedAt time.Time
}

func (s *Store) AddJoinLog(ctx context.Context, guildID, userID, username string, joinedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO join_log (guild_id, user_id, username, joined_at)
		VALUES ($1, $2, $3, $4)`,
		guildID, userID, username, joinedAt.Unix())
	return err
}

func (s *Store) GetRecentJoins(ctx context.Context, guildID string, limit int) ([]JoinLogEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT guild_id, user_id, username, joined_at
		FROM join_log WHERE guild_id = $1
		ORDER BY joined_at DESC LIMIT $2`,
		guildID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []JoinLogEntry
	for rows.Next() {
		var e JoinLogEntry
		var ts int64
		if err := rows.Scan(&e.GuildID, &e.UserID, &e.Username, &ts); err != nil {
			return nil, err
		}
		e.JoinedAt = time.Unix(ts, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) AddBannedUser(ctx context.Context, guildID, userID, username string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO banned_users (guild_id, user_id, username, banned_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (guild_id, user_id) DO UPDATE SET
			username  = EXCLUDED.username,
			banned_at = EXCLUDED.banned_at`,
		guildID, userID, username, time.Now().Unix())
	return err
}

func (s *Store) GetRecentBannedUsers(ctx context.Context, guildID string, limit int) ([]BannedUserEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT guild_id, user_id, username, banned_at
		FROM banned_users WHERE guild_id = $1
		ORDER BY banned_at DESC LIMIT $2`,
		guildID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []BannedUserEntry
	for rows.Next() {
		var e BannedUserEntry
		var ts int64
		if err := rows.Scan(&e.GuildID, &e.UserID, &e.Username, &ts); err != nil {
			return nil, err
		}
		e.BannedAt = time.Unix(ts, 0)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ── Shadow mutes ──────────────────────────────────────────────────────────────

type ShadowMuteEntry struct {
	ID        int64
	GuildID   string
	UserID    string
	MutedBy   string
	Reason    string
	CreatedAt time.Time
	ExpiresAt *time.Time // nil = permanent
}

func (s *Store) AddShadowMute(ctx context.Context, guildID, userID, mutedBy, reason string, expiresAt *time.Time) error {
	var expiresUnix *int64
	if expiresAt != nil {
		v := expiresAt.Unix()
		expiresUnix = &v
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO shadow_mutes (guild_id, user_id, muted_by, reason, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (guild_id, user_id) DO UPDATE SET
			muted_by   = EXCLUDED.muted_by,
			reason     = EXCLUDED.reason,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at`,
		guildID, userID, mutedBy, reason, time.Now().Unix(), expiresUnix)
	return err
}

func (s *Store) RemoveShadowMute(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM shadow_mutes WHERE guild_id = $1 AND user_id = $2`,
		guildID, userID)
	return err
}

func (s *Store) IsShadowMuted(ctx context.Context, guildID, userID string) (bool, error) {
	now := time.Now().Unix()
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM shadow_mutes
		WHERE guild_id = $1 AND user_id = $2
		AND (expires_at IS NULL OR expires_at > $3)`,
		guildID, userID, now).Scan(&count)
	return count > 0, err
}

func (s *Store) ListShadowMutes(ctx context.Context, guildID string) ([]ShadowMuteEntry, error) {
	now := time.Now().Unix()
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, guild_id, user_id, muted_by, reason, created_at, expires_at
		FROM shadow_mutes
		WHERE guild_id = $1
		AND (expires_at IS NULL OR expires_at > $2)
		ORDER BY created_at DESC`,
		guildID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []ShadowMuteEntry
	for rows.Next() {
		var e ShadowMuteEntry
		var createdAt int64
		var expiresAt *int64
		if err := rows.Scan(&e.ID, &e.GuildID, &e.UserID, &e.MutedBy, &e.Reason, &createdAt, &expiresAt); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(createdAt, 0)
		if expiresAt != nil {
			t := time.Unix(*expiresAt, 0)
			e.ExpiresAt = &t
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) CleanupExpiredShadowMutes(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM shadow_mutes WHERE expires_at IS NOT NULL AND expires_at <= $1`,
		time.Now().Unix())
	return err
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

// ── Onboarding sessions ───────────────────────────────────────────────────────

type OnboardingSession struct {
	ID          int64
	GuildID     string
	UserID      string
	CaptchaCode string
	Attempts    int
	CreatedAt   time.Time
	ExpiresAt   time.Time
	// Status: "pending_captcha", "pending_quiz", "verified", "failed"
	Status string
}

func (s *Store) UpsertOnboardingSession(ctx context.Context, sess OnboardingSession) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO onboarding_sessions (guild_id, user_id, captcha_code, attempts, created_at, expires_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (guild_id, user_id) DO UPDATE SET
			captcha_code = EXCLUDED.captcha_code,
			attempts     = EXCLUDED.attempts,
			created_at   = EXCLUDED.created_at,
			expires_at   = EXCLUDED.expires_at,
			status       = EXCLUDED.status`,
		sess.GuildID, sess.UserID, sess.CaptchaCode, sess.Attempts,
		sess.CreatedAt.Unix(), sess.ExpiresAt.Unix(), sess.Status)
	return err
}

func (s *Store) GetOnboardingSession(ctx context.Context, guildID, userID string) (*OnboardingSession, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, guild_id, user_id, captcha_code, attempts, created_at, expires_at, status
		FROM onboarding_sessions WHERE guild_id = $1 AND user_id = $2`,
		guildID, userID)
	var sess OnboardingSession
	var createdAt, expiresAt int64
	err := row.Scan(&sess.ID, &sess.GuildID, &sess.UserID, &sess.CaptchaCode,
		&sess.Attempts, &createdAt, &expiresAt, &sess.Status)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	sess.CreatedAt = time.Unix(createdAt, 0)
	sess.ExpiresAt = time.Unix(expiresAt, 0)
	return &sess, nil
}

func (s *Store) UpdateOnboardingSession(ctx context.Context, guildID, userID, status string, attempts int) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE onboarding_sessions SET status = $1, attempts = $2
		WHERE guild_id = $3 AND user_id = $4`,
		status, attempts, guildID, userID)
	return err
}

func (s *Store) DeleteOnboardingSession(ctx context.Context, guildID, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM onboarding_sessions WHERE guild_id = $1 AND user_id = $2`,
		guildID, userID)
	return err
}

func (s *Store) CleanupExpiredOnboardingSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM onboarding_sessions WHERE expires_at < $1`, time.Now().Unix())
	return err
}

// ── Tickets ───────────────────────────────────────────────────────────────────

type Ticket struct {
	ID        int64
	GuildID   string
	UserID    string
	ChannelID string
	Status    string // "open" | "closed"
	CreatedAt time.Time
	ClosedAt  *time.Time // nil when open
}

func (s *Store) CreateTicket(ctx context.Context, guildID, userID, channelID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tickets (guild_id, user_id, channel_id, status, created_at)
		VALUES ($1, $2, $3, 'open', $4)`,
		guildID, userID, channelID, time.Now().Unix())
	return err
}

// GetOpenTicket returns the open ticket for a user on a guild, or nil if none.
func (s *Store) GetOpenTicket(ctx context.Context, guildID, userID string) (*Ticket, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, guild_id, user_id, channel_id, status, created_at, closed_at
		FROM tickets
		WHERE guild_id = $1 AND user_id = $2 AND status = 'open'
		LIMIT 1`,
		guildID, userID)
	var t Ticket
	var createdAt int64
	var closedAt int64
	err := row.Scan(&t.ID, &t.GuildID, &t.UserID, &t.ChannelID, &t.Status, &createdAt, &closedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if closedAt != 0 {
		v := time.Unix(closedAt, 0)
		t.ClosedAt = &v
	}
	return &t, nil
}

// CountOpenTickets returns the number of currently open tickets for a guild.
func (s *Store) CountOpenTickets(ctx context.Context, guildID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM tickets WHERE guild_id = $1 AND status = 'open'`,
		guildID).Scan(&n)
	return n, err
}

// CloseTicket marks the ticket for the given channel as closed.
func (s *Store) CloseTicket(ctx context.Context, channelID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE tickets SET status = 'closed', closed_at = $1
		WHERE channel_id = $2 AND status = 'open'`,
		time.Now().Unix(), channelID)
	return err
}

// GetTicketByChannel returns the ticket associated with a given channel ID.
func (s *Store) GetTicketByChannel(ctx context.Context, channelID string) (*Ticket, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, guild_id, user_id, channel_id, status, created_at, closed_at
		FROM tickets WHERE channel_id = $1 LIMIT 1`,
		channelID)
	var t Ticket
	var createdAt int64
	var closedAt int64
	err := row.Scan(&t.ID, &t.GuildID, &t.UserID, &t.ChannelID, &t.Status, &createdAt, &closedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t.CreatedAt = time.Unix(createdAt, 0)
	if closedAt != 0 {
		v := time.Unix(closedAt, 0)
		t.ClosedAt = &v
	}
	return &t, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isIgnorableMigrationError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate column name")
}
