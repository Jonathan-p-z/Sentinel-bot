package antihate

import (
	"context"
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
	"pute",
	"salope",
	"connasse",
	"michto",
	"michtoneuse",
	"michtonneuse",
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
	"pede",
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
	"retard",
	"retarded",
	"triso",
	"kys",
	"kill yourself",
	"suicide toi",
	"va te pendre",
	"pends toi",
	"egorge",
	"creve",
	"dechet humain",
	"slp",
	"bztmr",
	"ngr",
	"niga",
	"nig",
	"ngrs",
	"bgnl",
	"bgnle",
	"pd",
	"p d",
	"p0m",
	"trlz",
	"tpette",
	"tarlz",
	"slpe",
	"conas",
	"con asse",
	"micht",
	"mcht",
	"fmnz",
	"lgtv",
	"t vlo",
	"trny",
	"smale",
	"k y s",
	"g die",
	"p t e",
	"p u t e",
	"p*te",
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

	score := m.risk.AddRisk(guildID, msg.Author.ID, 65)
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
	return replacer.Replace(strings.ToLower(input))
}
