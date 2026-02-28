package antihate

import (
	"context"
	"testing"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/risk"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
	"go.uber.org/zap"
)

func TestDetectBlockedKeyword(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	auditLogger := audit.NewLogger(store, zap.NewNop())
	riskEngine := risk.NewEngine(config.RiskConfig{DecayPerMinute: 0, TTLMinutes: 60, TrustWeight: 0.5})
	module := New(riskEngine, auditLogger)

	msg := &discordgo.MessageCreate{Message: &discordgo.Message{ID: "1", ChannelID: "c1", GuildID: "g1", Author: &discordgo.User{ID: "u1"}, Content: "ce message est raciste"}}
	if _, flagged, _ := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); !flagged {
		t.Fatalf("expected hate speech flag")
	}
}

func TestIgnoreSafeMessage(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	auditLogger := audit.NewLogger(store, zap.NewNop())
	riskEngine := risk.NewEngine(config.RiskConfig{DecayPerMinute: 0, TTLMinutes: 60, TrustWeight: 0.5})
	module := New(riskEngine, auditLogger)

	msg := &discordgo.MessageCreate{Message: &discordgo.Message{ID: "1", ChannelID: "c1", GuildID: "g1", Author: &discordgo.User{ID: "u1"}, Content: "bonjour tout le monde"}}
	if _, flagged, _ := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); flagged {
		t.Fatalf("did not expect hate speech flag")
	}
}
