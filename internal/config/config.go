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
	DefaultLanguage           string         `yaml:"default_language"`
	RetentionDays             int            `yaml:"retention_days"`
	RulePreset                string         `yaml:"rule_preset"`
	Mode                      string         `yaml:"mode"`
	Health                    HealthConfig   `yaml:"health"`
	Risk                      RiskConfig     `yaml:"risk"`
	Trust                     TrustConfig    `yaml:"trust"`
	Thresholds                Thresholds     `yaml:"thresholds"`
	Actions                   ActionConfig   `yaml:"actions"`
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

type PlaybookConfig struct {
	LockdownMinutes   int `yaml:"lockdown_minutes"`
	StrictModeMinutes int `yaml:"strict_mode_minutes"`
	ExitStepSeconds   int `yaml:"exit_step_seconds"`
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
		Actions: ActionConfig{
			Enabled:          false,
			Delete:           20,
			Quarantine:       40,
			Timeout:          60,
			Ban:              80,
			TimeoutMinutes:   10,
			QuarantineRoleID: "",
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
		Playbook: PlaybookConfig{LockdownMinutes: 15, StrictModeMinutes: 10, ExitStepSeconds: 20},
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
	cfg.Actions.Enabled = envBool("ACTIONS_ENABLED", cfg.Actions.Enabled)
	cfg.Actions.TimeoutMinutes = envInt("ACTIONS_TIMEOUT_MINUTES", cfg.Actions.TimeoutMinutes)
	cfg.Actions.QuarantineRoleID = envString("QUARANTINE_ROLE_ID", cfg.Actions.QuarantineRoleID)
	cfg.Notifications.ChannelWarnEnabled = envBool("CHANNEL_WARN_ENABLED", cfg.Notifications.ChannelWarnEnabled)
	cfg.Notifications.DMWarnEnabled = envBool("DM_WARN_ENABLED", cfg.Notifications.DMWarnEnabled)
	cfg.Notifications.AuditToChannel = envBool("AUDIT_TO_CHANNEL", cfg.Notifications.AuditToChannel)
	cfg.Notifications.DailySummary = envBool("DAILY_SUMMARY", cfg.Notifications.DailySummary)
	cfg.Notifications.EmbedColors.Action = envInt("EMBED_COLOR_ACTION", cfg.Notifications.EmbedColors.Action)
	cfg.Notifications.EmbedColors.Warning = envInt("EMBED_COLOR_WARNING", cfg.Notifications.EmbedColors.Warning)
	cfg.Notifications.EmbedColors.Error = envInt("EMBED_COLOR_ERROR", cfg.Notifications.EmbedColors.Error)
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
