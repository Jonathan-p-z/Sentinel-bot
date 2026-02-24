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
		if blocked || hasKeywords(msg.Content) {
			suspicious = true
			detail = "suspicious link: " + normalized
			rule := "domain_or_keyword"
			current := "1link"
			threshold := "1"
			auditDetail := fmt.Sprintf("type=PHISHING rule=%s value=%s threshold=%s url=%s", rule, current, threshold, normalized)
			m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_phishing", auditDetail)
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
