package antihate

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
)

const Category = "hate"

type Config struct {
	Enabled              bool
	Patterns             []string
	Allowlist            []string
	TimeoutMinutes       int
	ForgiveAfterDays     int
	DeleteInAuditMode    bool
	FallbackReasonPrefix string
}

type Module struct {
	cfg      Config
	store    *storage.Store
	audit    *audit.Logger
	patterns []compiledPattern
}

type compiledPattern struct {
	id  string
	re  *regexp.Regexp
	raw string
}

type Result struct {
	Matched    bool
	ReasonCode string
	Action     string
	Count      int
	Summary    string
	Level      string
	Err        error
}

func New(cfg Config, store *storage.Store, auditLogger *audit.Logger) *Module {
	module := &Module{cfg: cfg, store: store, audit: auditLogger}
	module.patterns = compilePatterns(cfg.Patterns, cfg.FallbackReasonPrefix)
	if module.cfg.TimeoutMinutes <= 0 {
		module.cfg.TimeoutMinutes = 60
	}
	if module.cfg.FallbackReasonPrefix == "" {
		module.cfg.FallbackReasonPrefix = "pattern"
	}
	return module
}

func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate, guildID string, auditOnly bool) Result {
	if !m.cfg.Enabled || msg == nil || msg.Author == nil {
		return Result{}
	}
	matched, reasonCode := m.Detect(msg.Content)
	if !matched {
		return Result{}
	}

	action := "delete"
	if !auditOnly || m.cfg.DeleteInAuditMode {
		_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
	}

	forgive := time.Duration(0)
	if m.cfg.ForgiveAfterDays > 0 {
		forgive = time.Duration(m.cfg.ForgiveAfterDays) * 24 * time.Hour
	}
	count, err := m.store.IncrementInfraction(ctx, guildID, msg.Author.ID, Category, action, forgive)
	if err != nil {
		return Result{Matched: true, ReasonCode: reasonCode, Action: action, Err: err}
	}

	level := audit.LevelHigh
	switch {
	case count >= 3:
		action = "ban"
		level = audit.LevelCrit
	case count == 2:
		action = "timeout_1h"
		level = audit.LevelHigh
	default:
		action = "delete"
		level = audit.LevelHigh
	}

	if !auditOnly {
		switch action {
		case "timeout_1h":
			until := time.Now().Add(time.Duration(m.cfg.TimeoutMinutes) * time.Minute)
			if err := session.GuildMemberTimeout(guildID, msg.Author.ID, &until); err != nil {
				action = "timeout_failed"
			}
		case "ban":
			if err := session.GuildBanCreateWithReason(guildID, msg.Author.ID, "Sentinel Adaptive anti-hate escalation", 0); err != nil {
				action = "ban_failed"
			}
		}
	}

	contentHash := hashContent(msg.Content)
	detail := fmt.Sprintf("type=HATE_SPEECH rule=blacklist_match value=count_%d threshold=1 action=%s reason=%s content_hash=%s", count, action, reasonCode, contentHash)
	m.audit.Log(ctx, level, guildID, msg.Author.ID, "anti_hate", detail)

	summary := fmt.Sprintf("Reason: matched pattern %q | Count: %d", reasonCode, count)
	if auditOnly {
		summary += " | mode=audit"
	}
	return Result{Matched: true, ReasonCode: reasonCode, Action: action, Count: count, Summary: summary, Level: level}
}

func (m *Module) Detect(content string) (bool, string) {
	normalized := normalize(content)
	if normalized == "" {
		return false, ""
	}
	for _, allowed := range m.cfg.Allowlist {
		allow := normalize(allowed)
		if allow != "" && strings.Contains(normalized, allow) {
			return false, ""
		}
	}
	for _, pattern := range m.patterns {
		if pattern.re.MatchString(normalized) {
			return true, pattern.id
		}
	}
	return false, ""
}

func compilePatterns(patterns []string, fallbackPrefix string) []compiledPattern {
	compiled := make([]compiledPattern, 0, len(patterns))
	if fallbackPrefix == "" {
		fallbackPrefix = "pattern"
	}
	for index, raw := range patterns {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		id := fmt.Sprintf("%s_%02d", fallbackPrefix, index+1)
		expr := trimmed
		if !looksLikeRegex(trimmed) {
			expr = `\b` + regexp.QuoteMeta(strings.ToLower(trimmed)) + `\b`
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			continue
		}
		compiled = append(compiled, compiledPattern{id: id, re: re, raw: trimmed})
	}
	return compiled
}

func looksLikeRegex(value string) bool {
	for _, marker := range []string{"\\b", "[", "(", ".", "*", "+", "?", "|", "^", "$"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func hashContent(content string) string {
	sum := sha1.Sum([]byte(content))
	return hex.EncodeToString(sum[:8])
}
