package antiphishing

import (
	"context"
	"fmt"
	"strings"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/risk"
	"sentinel-adaptive/internal/utils"

	"github.com/bwmarrin/discordgo"
)

var keywordSignals = []string{"nitro", "free", "claim", "gift", "steam", "giveaway"}
var trustedGIFDomains = map[string]struct{}{
	"tenor.com":       {},
	"www.tenor.com":   {},
	"media.tenor.com": {},
	"c.tenor.com":     {},
}

type Module struct {
	risk  *risk.Engine
	audit *audit.Logger
}

type MessageContext struct {
	ChannelType discordgo.ChannelType
}

func New(riskEngine *risk.Engine, auditLogger *audit.Logger) *Module {
	return &Module{risk: riskEngine, audit: auditLogger}
}

func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate, guildID string, allowlist, blocklist map[string]struct{}, phishingRisk int, auditOnly bool, messageContext MessageContext) (float64, bool, string) {
	urls := utils.ExtractURLs(msg.Content)
	if len(urls) == 0 {
		return 0, false, ""
	}

	suspicious := false
	detail := ""
	for _, raw := range urls {
		normalized, domain, err := utils.NormalizeURL(raw)
		if err != nil {
			continue
		}

		if isTrustedGIFURL(raw, domain) {
			continue
		}

		allowed, blocked := utils.DomainMatch(domain, allowlist, blocklist)
		if allowed {
			continue
		}
		if blocked || shouldFlagByKeywords(msg.Content, messageContext) {
			suspicious = true
			reason := "keywords"
			if blocked {
				reason = "blocklist"
			}
			detail = fmt.Sprintf("user=<@%s> reason=%s url=%s message=%q", msg.Author.ID, reason, normalized, msg.Content)
			m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_phishing", detail)
			break
		}
	}

	if !suspicious {
		return 0, false, ""
	}

	score := m.risk.AddRisk(guildID, msg.Author.ID, float64(phishingRisk))
	if !auditOnly {
		_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
	}
	return score, true, detail
}

func shouldFlagByKeywords(content string, messageContext MessageContext) bool {
	if messageContext.ChannelType == discordgo.ChannelTypeGuildPrivateThread {
		return false
	}
	return hasKeywords(content)
}

func hasKeywords(content string) bool {
	lower := strings.ToLower(content)
	for _, keyword := range keywordSignals {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func isTrustedGIFDomain(domain string) bool {
	domain = strings.ToLower(domain)
	if _, ok := trustedGIFDomains[domain]; ok {
		return true
	}
	return strings.HasSuffix(domain, ".tenor.com")
}

func isTrustedGIFURL(raw, domain string) bool {
	if isTrustedGIFDomain(domain) {
		return true
	}
	raw = strings.ToLower(raw)
	return strings.Contains(raw, "://tenor.com/") ||
		strings.Contains(raw, "://www.tenor.com/") ||
		strings.Contains(raw, "://media.tenor.com/") ||
		strings.Contains(raw, "://c.tenor.com/")
}
