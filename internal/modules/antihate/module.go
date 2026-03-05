package antihate

import (
	"context"
	"fmt"
	"strings"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/risk"

	"github.com/bwmarrin/discordgo"
)

var blockedKeywords = []string{
	"negre",
	"negresse",
	"negro",
	"nigger",
	"nigga",
	"bougnoule",
	"bicot",
	"raton",
	"chinetoque",
	"gniack",
	"youtre",
	"sale juif",
	"sale arabe",
	"sale noir",
	"garce",
	"trainee",
	"catin",
	"souillon",
	"poufiasse",
	"pouffiasse",
	"slut",
	"whore",
	"cunt",
	"bitch",
	"feminazi",
	"mal baisee",
	"malbaisee",
	"pedale",
	"tarlouze",
	"tapette",
	"faggot",
	"fag",
	"gouine",
	"tranny",
	"shemale",
	"travlo",
	"mongol",
	"gogol",
	"attarde",
	"retarded",
	"triso",
	"kys",
	"kill yourself",
	"suicide toi",
	"va te pendre",
	"pends toi",
	"egorge",
	"dechet humain",
	"slp",
	"bztmr",
	"ngr",
	"niga",
	"nig",
	"ngrs",
	"bgnl",
	"bgnle",
	"p0m",
	"trlz",
	"tpette",
	"tarlz",
	"micht",
	"mcht",
	"fmnz",
	"lgtv",
	"t vlo",
	"trny",
	"smale",
	"k y s",
	"g die",
	"n a z i",
	"n e g r e",
	"s s",
	"1488",
	"88",
	"htlr",
	"adf",
	"fhrer",
	"jte viol",
	"jte viole",
	"jte violerai",
	"jte violerais",
	"jvais te violer",
	"jvai te violer",
	"jvais te viol",
	"je vais te violer",
	"je vais te viol",
	"violer ta mere",
	"violer ta soeur",
	"violer ta maman",
	"jte v ol",
	"jte v1ol",
	"jte v i o l e",
	"va te faire violer",
	"go te faire violer",
	"jte vrape",
	"jte rape",
	"jte r4pe",
	"rape",
	"r4pe",
	"vrape",
	"viol",
	"vi0l",
	"vi0l",
	"violer",
	"vi0ler",
	"v1ol",
}

func init() {
	// Keep both original and uppercase variants in the keyword list.
	expanded := make([]string, 0, len(blockedKeywords)*2)
	seen := make(map[string]struct{}, len(blockedKeywords)*2)

	for _, keyword := range blockedKeywords {
		if _, ok := seen[keyword]; !ok {
			expanded = append(expanded, keyword)
			seen[keyword] = struct{}{}
		}

		upper := strings.ToUpper(keyword)
		if _, ok := seen[upper]; !ok {
			expanded = append(expanded, upper)
			seen[upper] = struct{}{}
		}
	}

	blockedKeywords = expanded
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

	matched, ok := findBlockedKeyword(content)
	if !ok {
		return 0, false, ""
	}

	detail := fmt.Sprintf("user=<@%s> keyword=%q message=%q", msg.Author.ID, matched, msg.Content)
	m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_hate", detail)
	if !auditOnly {
		_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
	}

	score := m.risk.AddRisk(guildID, msg.Author.ID, 65)
	return score, true, detail
}

func findBlockedKeyword(content string) (string, bool) {
	tokens := strings.Fields(content)
	for _, keyword := range blockedKeywords {
		normalizedKeyword := strings.TrimSpace(strings.ToLower(keyword))
		if normalizedKeyword == "" {
			continue
		}
		if strings.Contains(normalizedKeyword, " ") {
			if containsPhraseWithBoundaries(content, normalizedKeyword) {
				return keyword, true
			}
			continue
		}
		for _, token := range tokens {
			if token == normalizedKeyword {
				return keyword, true
			}
		}
	}
	return "", false
}

func containsPhraseWithBoundaries(content, phrase string) bool {
	start := 0
	for {
		idx := strings.Index(content[start:], phrase)
		if idx < 0 {
			return false
		}
		idx += start
		end := idx + len(phrase)
		leftOK := idx == 0 || content[idx-1] == ' '
		rightOK := end == len(content) || content[end] == ' '
		if leftOK && rightOK {
			return true
		}
		start = idx + 1
	}
}

func normalizeText(input string) string {
	replacer := strings.NewReplacer(
		"à", "a", "á", "a", "â", "a", "ä", "a",
		"è", "e", "é", "e", "ê", "e", "ë", "e",
		"ì", "i", "í", "i", "î", "i", "ï", "i",
		"ò", "o", "ó", "o", "ô", "o", "ö", "o",
		"ù", "u", "ú", "u", "û", "u", "ü", "u",
		"ç", "c",
		"'", " ",
		"-", " ",
		"_", " ",
		".", " ",
		",", " ",
		"!", " ",
		"?", " ",
		"*", " ",
		"@", "a",
	)
	normalized := replacer.Replace(strings.ToLower(input))
	return strings.Join(strings.Fields(normalized), " ")
}
