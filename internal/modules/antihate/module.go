package antihate

import (
	"context"
	"strings"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/risk"

	"github.com/bwmarrin/discordgo"
)

var blockedKeywords = []string{
	"raciste",
	"racisme",
	"homophobe",
	"homophobie",
	"xenophobe",
	"xenophobie",
	"transphobe",
	"transphobie",
	"antisemite",
	"antisemitisme",
}

type Module struct {
	risk  *risk.Engine
	audit *audit.Logger
}

func New(riskEngine *risk.Engine, auditLogger *audit.Logger) *Module {
	return &Module{risk: riskEngine, audit: auditLogger}
}

func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate, guildID string, auditOnly bool) (float64, bool, string) {
	if msg == nil || msg.Content == "" {
		return 0, false, ""
	}

	content := normalizeText(msg.Content)
	if !containsBlockedKeyword(content) {
		return 0, false, ""
	}

	detail := "hate speech keyword detected"
	m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_hate", detail)
	if !auditOnly {
		_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
	}

	score := m.risk.AddRisk(guildID, msg.Author.ID, 30)
	return score, true, detail
}

func containsBlockedKeyword(content string) bool {
	for _, keyword := range blockedKeywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func normalizeText(input string) string {
	replacer := strings.NewReplacer(
		"à", "a", "á", "a", "â", "a", "ä", "a",
		"è", "e", "é", "e", "ê", "e", "ë", "e",
		"ì", "i", "í", "i", "î", "i", "ï", "i",
		"ò", "o", "ó", "o", "ô", "o", "ö", "o",
		"ù", "u", "ú", "u", "û", "u", "ü", "u",
		"ç", "c",
	)
	return replacer.Replace(strings.ToLower(input))
}
