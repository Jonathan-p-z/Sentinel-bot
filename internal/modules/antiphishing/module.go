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

var urlThreatSignals = []string{"kys", "kill", "suicide", "violer", "rape", "egorge", "snuff", "gore"}

type Module struct {
	risk  *risk.Engine
	audit *audit.Logger
}

func New(riskEngine *risk.Engine, auditLogger *audit.Logger) *Module {
	return &Module{risk: riskEngine, audit: auditLogger}
}

func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate, guildID string, allowlist, blocklist map[string]struct{}, phishingRisk int, auditOnly bool) (float64, bool, string) {
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

		allowed, blocked := utils.DomainMatch(domain, allowlist, blocklist)
		if allowed {
			continue
		}
		if isTrustedGIFDomain(domain) {
			if blocked || hasURLThreatIndicators(normalized) {
				suspicious = true
				reason := "threat_indicators"
				if blocked {
					reason = "blocklist"
				}
				detail = fmt.Sprintf("user=<@%s> reason=%s url=%s message=%q", msg.Author.ID, reason, normalized, msg.Content)
				m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_phishing", detail)
				break
			}
			continue
		}
		if blocked || hasKeywords(msg.Content) {
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

func hasURLThreatIndicators(url string) bool {
	lower := strings.ToLower(url)
	for _, indicator := range urlThreatSignals {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}
