package config

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DiscordToken              string         `yaml:"discord_token"`
	DatabasePath              string         `yaml:"database_path"`
	LogLevel                  string         `yaml:"log_level"`
	DefaultSecurityLogChannel string         `yaml:"default_security_log_channel"`
	DefaultAuditLogChannel    string         `yaml:"default_audit_log_channel"`
	DefaultLanguage           string         `yaml:"default_language"`
	RetentionDays             int            `yaml:"retention_days"`
	RulePreset                string         `yaml:"rule_preset"`
	Mode                      string         `yaml:"mode"`
	Health                    HealthConfig   `yaml:"health"`
	Risk                      RiskConfig     `yaml:"risk"`
	Trust                     TrustConfig    `yaml:"trust"`
	Thresholds                Thresholds     `yaml:"thresholds"`
	Nuke                      NukeConfig     `yaml:"nuke"`
	Hate                      HateConfig     `yaml:"hate"`
	Actions                   ActionConfig   `yaml:"actions"`
	Log                       LogConfig      `yaml:"log"`
	Notifications             NotifyConfig   `yaml:"notifications"`
	Playbook                  PlaybookConfig `yaml:"playbook"`
}

type HealthConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

type RiskConfig struct {
	DecayPerMinute float64 `yaml:"decay_per_minute"`
	TTLMinutes     int     `yaml:"ttl_minutes"`
	TrustWeight    float64 `yaml:"trust_weight"`
}

type TrustConfig struct {
	MaxScore   float64 `yaml:"max_score"`
	TTLMinutes int     `yaml:"ttl_minutes"`
}

type Thresholds struct {
	SpamMessages       int `yaml:"spam_messages"`
	SpamWindowSeconds  int `yaml:"spam_window_seconds"`
	RaidJoins          int `yaml:"raid_joins"`
	RaidWindowSeconds  int `yaml:"raid_window_seconds"`
	PhishingRisk       int `yaml:"phishing_risk"`
	BurstLinks         int `yaml:"burst_links"`
	BurstWindowSeconds int `yaml:"burst_window_seconds"`
}

type NukeConfig struct {
	Enabled             bool `yaml:"enabled"`
	WindowSeconds       int  `yaml:"window_seconds"`
	ChannelDelete       int  `yaml:"channel_delete"`
	ChannelCreate       int  `yaml:"channel_create"`
	ChannelUpdate       int  `yaml:"channel_update"`
	RoleDelete          int  `yaml:"role_delete"`
	RoleCreate          int  `yaml:"role_create"`
	RoleUpdate          int  `yaml:"role_update"`
	WebhookUpdate       int  `yaml:"webhook_update"`
	BanAdd              int  `yaml:"ban_add"`
	GuildUpdate         int  `yaml:"guild_update"`
	ExemptThreshold     int  `yaml:"exempt_threshold"`
	ExemptWindowSeconds int  `yaml:"exempt_window_seconds"`
}

type HateConfig struct {
	Enabled           bool     `yaml:"enabled"`
	Patterns          []string `yaml:"patterns"`
	Allowlist         []string `yaml:"allowlist"`
	TimeoutMinutes    int      `yaml:"timeout_minutes"`
	ForgiveAfterDays  int      `yaml:"forgive_after_days"`
	DeleteInAuditMode bool     `yaml:"delete_in_audit_mode"`
}

type PlaybookConfig struct {
	LockdownMinutes   int  `yaml:"lockdown_minutes"`
	StrictModeMinutes int  `yaml:"strict_mode_minutes"`
	ExitStepSeconds   int  `yaml:"exit_step_seconds"`
	LockdownSlowmode  int  `yaml:"lockdown_slowmode_seconds"`
	LockdownDenySend  bool `yaml:"lockdown_deny_send"`
}

type ActionConfig struct {
	Enabled          bool    `yaml:"enabled"`
	Delete           float64 `yaml:"delete"`
	Quarantine       float64 `yaml:"quarantine"`
	Timeout          float64 `yaml:"timeout"`
	Ban              float64 `yaml:"ban"`
	TimeoutMinutes   int     `yaml:"timeout_minutes"`
	QuarantineRoleID string  `yaml:"quarantine_role_id"`
}

type LogConfig struct {
	DiscordMinLevel       string   `yaml:"discord_min_level"`
	DiscordCategories     []string `yaml:"discord_categories"`
	DiscordRateLimitSec   int      `yaml:"discord_rate_limit_seconds"`
	DigestIntervalMinutes int      `yaml:"digest_interval_minutes"`
	AlertCooldownMinutes  int      `yaml:"alert_cooldown_minutes"`
	WarnRareMinutes       int      `yaml:"warn_rare_minutes"`
	DedupWindowSeconds    int      `yaml:"dedup_window_seconds"`
}

type NotifyConfig struct {
	ChannelWarnEnabled bool        `yaml:"channel_warn_enabled"`
	DMWarnEnabled      bool        `yaml:"dm_warn_enabled"`
	AuditToChannel     bool        `yaml:"audit_to_channel"`
	DailySummary       bool        `yaml:"daily_summary"`
	EmbedColors        EmbedColors `yaml:"embed_colors"`
}

type EmbedColors struct {
	Action  int `yaml:"action"`
	Warning int `yaml:"warning"`
	Error   int `yaml:"error"`
}

func DefaultConfig() Config {
	return Config{
		DatabasePath:              "/data/sentinel.db",
		LogLevel:                  "info",
		RetentionDays:             14,
		RulePreset:                "medium",
		Mode:                      "normal",
		DefaultSecurityLogChannel: "",
		DefaultAuditLogChannel:    "",
		DefaultLanguage:           "fr",
		Health:                    HealthConfig{Enabled: false, Addr: ":8080"},
		Risk:                      RiskConfig{DecayPerMinute: 0.5, TTLMinutes: 60, TrustWeight: 0.5},
		Trust:                     TrustConfig{MaxScore: 100, TTLMinutes: 1440},
		Thresholds: Thresholds{
			SpamMessages:       6,
			SpamWindowSeconds:  8,
			RaidJoins:          6,
			RaidWindowSeconds:  10,
			PhishingRisk:       30,
			BurstLinks:         3,
			BurstWindowSeconds: 20,
		},
		Nuke: NukeConfig{
			Enabled:             true,
			WindowSeconds:       20,
			ChannelDelete:       3,
			ChannelCreate:       6,
			ChannelUpdate:       6,
			RoleDelete:          3,
			RoleCreate:          6,
			RoleUpdate:          6,
			WebhookUpdate:       4,
			BanAdd:              3,
			GuildUpdate:         2,
			ExemptThreshold:     20,
			ExemptWindowSeconds: 10,
		},
		Hate: HateConfig{
			Enabled:           true,
			Patterns:          []string{},
			Allowlist:         []string{},
			TimeoutMinutes:    60,
			ForgiveAfterDays:  30,
			DeleteInAuditMode: false,
		},
		Actions: ActionConfig{
			Enabled:          false,
			Delete:           20,
			Quarantine:       40,
			Timeout:          60,
			Ban:              80,
			TimeoutMinutes:   10,
			QuarantineRoleID: "",
		},
		Log: LogConfig{
			DiscordMinLevel:       "HIGH",
			DiscordCategories:     []string{"anti_hate", "anti_phishing", "anti_spam", "anti_raid", "anti_nuke", "raid_lockdown", "risk_action", "action_failed", "nuke_timeout"},
			DiscordRateLimitSec:   10,
			DigestIntervalMinutes: 15,
			AlertCooldownMinutes:  10,
			WarnRareMinutes:       60,
			DedupWindowSeconds:    60,
		},
		Notifications: NotifyConfig{
			ChannelWarnEnabled: true,
			DMWarnEnabled:      true,
			AuditToChannel:     true,
			DailySummary:       true,
			EmbedColors: EmbedColors{
				Action:  0xF59E0B,
				Warning: 0xEF4444,
				Error:   0xF97316,
			},
		},
		Playbook: PlaybookConfig{LockdownMinutes: 15, StrictModeMinutes: 10, ExitStepSeconds: 20, LockdownSlowmode: 10, LockdownDenySend: true},
	}
}

func Load() (Config, error) {
	cfg := DefaultConfig()

	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "config.yaml"
	}
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, err
		}
	}

	applyEnv(&cfg)
	if cfg.DiscordToken == "" {
		return Config{}, errors.New("DISCORD_TOKEN is required")
	}

	cfg.Mode = normalizeMode(cfg.Mode)
	cfg.RulePreset = normalizePreset(cfg.RulePreset)
	applyPreset(&cfg)

	return cfg, nil
}

func applyEnv(cfg *Config) {
	cfg.DiscordToken = envString("DISCORD_TOKEN", cfg.DiscordToken)
	cfg.DatabasePath = envString("DATABASE_PATH", cfg.DatabasePath)
	cfg.LogLevel = envString("LOG_LEVEL", cfg.LogLevel)
	cfg.DefaultSecurityLogChannel = envString("DEFAULT_SECURITY_LOG_CHANNEL", cfg.DefaultSecurityLogChannel)
	cfg.DefaultAuditLogChannel = envString("DEFAULT_AUDIT_LOG_CHANNEL", cfg.DefaultAuditLogChannel)
	cfg.DefaultLanguage = envString("DEFAULT_LANGUAGE", cfg.DefaultLanguage)
	cfg.RetentionDays = envInt("RETENTION_DAYS", cfg.RetentionDays)
	cfg.RulePreset = envString("RULE_PRESET", cfg.RulePreset)
	cfg.Mode = envString("MODE", cfg.Mode)
	cfg.Health.Enabled = envBool("HEALTH_ENABLED", cfg.Health.Enabled)
	cfg.Health.Addr = envString("HEALTH_ADDR", cfg.Health.Addr)
	cfg.Thresholds.SpamMessages = envInt("SPAM_MESSAGES", cfg.Thresholds.SpamMessages)
	cfg.Thresholds.SpamWindowSeconds = envInt("SPAM_WINDOW_SECONDS", cfg.Thresholds.SpamWindowSeconds)
	cfg.Thresholds.RaidJoins = envInt("RAID_JOINS", cfg.Thresholds.RaidJoins)
	cfg.Thresholds.RaidWindowSeconds = envInt("RAID_WINDOW_SECONDS", cfg.Thresholds.RaidWindowSeconds)
	cfg.Thresholds.PhishingRisk = envInt("PHISHING_RISK", cfg.Thresholds.PhishingRisk)
	cfg.Thresholds.BurstLinks = envInt("BURST_LINKS", cfg.Thresholds.BurstLinks)
	cfg.Thresholds.BurstWindowSeconds = envInt("BURST_WINDOW_SECONDS", cfg.Thresholds.BurstWindowSeconds)
	cfg.Nuke.Enabled = envBool("NUKE_ENABLED", cfg.Nuke.Enabled)
	cfg.Nuke.WindowSeconds = envInt("NUKE_WINDOW_SECONDS", cfg.Nuke.WindowSeconds)
	cfg.Nuke.ChannelDelete = envInt("NUKE_CHANNEL_DELETE", cfg.Nuke.ChannelDelete)
	cfg.Nuke.ChannelCreate = envInt("NUKE_CHANNEL_CREATE", cfg.Nuke.ChannelCreate)
	cfg.Nuke.ChannelUpdate = envInt("NUKE_CHANNEL_UPDATE", cfg.Nuke.ChannelUpdate)
	cfg.Nuke.RoleDelete = envInt("NUKE_ROLE_DELETE", cfg.Nuke.RoleDelete)
	cfg.Nuke.RoleCreate = envInt("NUKE_ROLE_CREATE", cfg.Nuke.RoleCreate)
	cfg.Nuke.RoleUpdate = envInt("NUKE_ROLE_UPDATE", cfg.Nuke.RoleUpdate)
	cfg.Nuke.WebhookUpdate = envInt("NUKE_WEBHOOK_UPDATE", cfg.Nuke.WebhookUpdate)
	cfg.Nuke.BanAdd = envInt("NUKE_BAN_ADD", cfg.Nuke.BanAdd)
	cfg.Nuke.GuildUpdate = envInt("NUKE_GUILD_UPDATE", cfg.Nuke.GuildUpdate)
	cfg.Nuke.ExemptThreshold = envInt("NUKE_EXEMPT_THRESHOLD", cfg.Nuke.ExemptThreshold)
	cfg.Nuke.ExemptWindowSeconds = envInt("NUKE_EXEMPT_WINDOW_SECONDS", cfg.Nuke.ExemptWindowSeconds)
	cfg.Hate.Enabled = envBool("HATE_ENABLED", cfg.Hate.Enabled)
	cfg.Hate.TimeoutMinutes = envInt("HATE_TIMEOUT_MINUTES", cfg.Hate.TimeoutMinutes)
	cfg.Hate.ForgiveAfterDays = envInt("HATE_FORGIVE_AFTER_DAYS", cfg.Hate.ForgiveAfterDays)
	cfg.Hate.DeleteInAuditMode = envBool("HATE_DELETE_IN_AUDIT_MODE", cfg.Hate.DeleteInAuditMode)
	if patterns := envString("HATE_PATTERNS", ""); patterns != "" {
		parts := strings.Split(patterns, ",")
		cfg.Hate.Patterns = cfg.Hate.Patterns[:0]
		for _, part := range parts {
			value := strings.TrimSpace(part)
			if value != "" {
				cfg.Hate.Patterns = append(cfg.Hate.Patterns, value)
			}
		}
	}
	if allowlist := envString("HATE_ALLOWLIST", ""); allowlist != "" {
		parts := strings.Split(allowlist, ",")
		cfg.Hate.Allowlist = cfg.Hate.Allowlist[:0]
		for _, part := range parts {
			value := strings.TrimSpace(part)
			if value != "" {
				cfg.Hate.Allowlist = append(cfg.Hate.Allowlist, value)
			}
		}
	}
	cfg.Actions.Enabled = envBool("ACTIONS_ENABLED", cfg.Actions.Enabled)
	cfg.Actions.TimeoutMinutes = envInt("ACTIONS_TIMEOUT_MINUTES", cfg.Actions.TimeoutMinutes)
	cfg.Actions.QuarantineRoleID = envString("QUARANTINE_ROLE_ID", cfg.Actions.QuarantineRoleID)
	cfg.Log.DiscordMinLevel = envString("LOG_DISCORD_MIN_LEVEL", cfg.Log.DiscordMinLevel)
	cfg.Log.DiscordRateLimitSec = envInt("LOG_DISCORD_RATE_LIMIT_SECONDS", cfg.Log.DiscordRateLimitSec)
	cfg.Log.DigestIntervalMinutes = envInt("LOG_DIGEST_INTERVAL_MINUTES", cfg.Log.DigestIntervalMinutes)
	cfg.Log.AlertCooldownMinutes = envInt("LOG_ALERT_COOLDOWN_MINUTES", cfg.Log.AlertCooldownMinutes)
	cfg.Log.WarnRareMinutes = envInt("LOG_WARN_RARE_MINUTES", cfg.Log.WarnRareMinutes)
	cfg.Log.DedupWindowSeconds = envInt("LOG_DEDUP_WINDOW_SECONDS", cfg.Log.DedupWindowSeconds)
	if categories := envString("LOG_DISCORD_CATEGORIES", ""); categories != "" {
		parts := strings.Split(categories, ",")
		cfg.Log.DiscordCategories = cfg.Log.DiscordCategories[:0]
		for _, part := range parts {
			value := strings.TrimSpace(strings.ToLower(part))
			if value != "" {
				cfg.Log.DiscordCategories = append(cfg.Log.DiscordCategories, value)
			}
		}
	}
	cfg.Notifications.ChannelWarnEnabled = envBool("CHANNEL_WARN_ENABLED", cfg.Notifications.ChannelWarnEnabled)
	cfg.Notifications.DMWarnEnabled = envBool("DM_WARN_ENABLED", cfg.Notifications.DMWarnEnabled)
	cfg.Notifications.AuditToChannel = envBool("AUDIT_TO_CHANNEL", cfg.Notifications.AuditToChannel)
	cfg.Notifications.DailySummary = envBool("DAILY_SUMMARY", cfg.Notifications.DailySummary)
	cfg.Notifications.EmbedColors.Action = envInt("EMBED_COLOR_ACTION", cfg.Notifications.EmbedColors.Action)
	cfg.Notifications.EmbedColors.Warning = envInt("EMBED_COLOR_WARNING", cfg.Notifications.EmbedColors.Warning)
	cfg.Notifications.EmbedColors.Error = envInt("EMBED_COLOR_ERROR", cfg.Notifications.EmbedColors.Error)
	cfg.Playbook.LockdownSlowmode = envInt("LOCKDOWN_SLOWMODE_SECONDS", cfg.Playbook.LockdownSlowmode)
	cfg.Playbook.LockdownDenySend = envBool("LOCKDOWN_DENY_SEND", cfg.Playbook.LockdownDenySend)
}

func BuildLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "json"
	cfg.EncoderConfig.TimeKey = "time"
	cfg.EncoderConfig.MessageKey = "message"
	cfg.EncoderConfig.LevelKey = "level"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	lvl := strings.ToLower(level)
	switch lvl {
	case "debug", "info", "warn", "error":
		cfg.Level = zap.NewAtomicLevelAt(parseLevel(lvl))
	default:
		cfg.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	return cfg.Build()
}

func parseLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if value := os.Getenv(key); value != "" {
		lower := strings.ToLower(value)
		return lower == "1" || lower == "true" || lower == "yes"
	}
	return fallback
}

func normalizeMode(value string) string {
	switch strings.ToLower(value) {
	case "audit":
		return "audit"
	default:
		return "normal"
	}
}

func normalizePreset(value string) string {
	switch strings.ToLower(value) {
	case "low", "medium", "high":
		return strings.ToLower(value)
	default:
		return "medium"
	}
}

func applyPreset(cfg *Config) {
	enabled := cfg.Actions.Enabled
	minutes := cfg.Actions.TimeoutMinutes
	roleID := cfg.Actions.QuarantineRoleID
	notify := cfg.Notifications

	switch cfg.RulePreset {
	case "low":
		cfg.Thresholds.SpamMessages = 8
		cfg.Thresholds.RaidJoins = 8
		cfg.Thresholds.PhishingRisk = 20
		cfg.Actions = ActionConfig{Enabled: enabled, Delete: 30, Quarantine: 55, Timeout: 75, Ban: 95, TimeoutMinutes: minutes, QuarantineRoleID: roleID}
		cfg.Notifications = notify
	case "high":
		cfg.Thresholds.SpamMessages = 4
		cfg.Thresholds.RaidJoins = 4
		cfg.Thresholds.PhishingRisk = 35
		cfg.Actions = ActionConfig{Enabled: enabled, Delete: 15, Quarantine: 30, Timeout: 50, Ban: 70, TimeoutMinutes: minutes, QuarantineRoleID: roleID}
		cfg.Notifications = notify
	default:
		cfg.Actions = ActionConfig{Enabled: enabled, Delete: 20, Quarantine: 40, Timeout: 60, Ban: 80, TimeoutMinutes: minutes, QuarantineRoleID: roleID}
		cfg.Notifications = notify
	}
}
