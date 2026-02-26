package antispam

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

func TestAntiSpamSlidingWindow(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	auditLogger := audit.NewLogger(store, zap.NewNop())
	riskEngine := risk.NewEngine(config.RiskConfig{DecayPerMinute: 0, TTLMinutes: 60, TrustWeight: 0.5})

	module := New(config.Thresholds{SpamMessages: 2, SpamWindowSeconds: 2}, riskEngine, auditLogger)
	msg := &discordgo.MessageCreate{Message: &discordgo.Message{ID: "1", ChannelID: "c1", GuildID: "g1", Author: &discordgo.User{ID: "u1"}}}

	if _, flagged := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); flagged {
		t.Fatalf("unexpected flag")
	}
	msg.Message.ID = "2"
	if _, flagged := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); !flagged {
		t.Fatalf("expected flag")
	}
}
