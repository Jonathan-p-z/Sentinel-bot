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

	if _, flagged, _ := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); flagged {
		t.Fatalf("unexpected flag")
	}
	msg.Message.ID = "2"
	if _, flagged, detail := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); !flagged {
		t.Fatalf("expected flag")
	} else if detail == "" {
		t.Fatalf("expected sanction detail evidence")
	}
}

func TestAntiSpamDuplicatePattern(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	auditLogger := audit.NewLogger(store, zap.NewNop())
	riskEngine := risk.NewEngine(config.RiskConfig{DecayPerMinute: 0, TTLMinutes: 60, TrustWeight: 0.5})

	module := New(config.Thresholds{SpamMessages: 6, SpamWindowSeconds: 10}, riskEngine, auditLogger)
	msg := &discordgo.MessageCreate{Message: &discordgo.Message{ID: "a1", ChannelID: "c1", GuildID: "g1", Author: &discordgo.User{ID: "u1"}, Content: "join my server"}}

	if _, flagged, _ := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); flagged {
		t.Fatalf("unexpected flag on first message")
	}
	msg.Message.ID = "a2"
	if _, flagged, _ := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); flagged {
		t.Fatalf("unexpected flag on second duplicate")
	}
	msg.Message.ID = "a3"
	if _, flagged, detail := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); !flagged {
		t.Fatalf("expected duplicate pattern flag")
	} else if detail == "" {
		t.Fatalf("expected detail for duplicate pattern")
	}
}

func TestAntiSpamMentionBurst(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	auditLogger := audit.NewLogger(store, zap.NewNop())
	riskEngine := risk.NewEngine(config.RiskConfig{DecayPerMinute: 0, TTLMinutes: 60, TrustWeight: 0.5})

	module := New(config.Thresholds{SpamMessages: 8, SpamWindowSeconds: 10}, riskEngine, auditLogger)
	msg := &discordgo.MessageCreate{Message: &discordgo.Message{
		ID:        "m1",
		ChannelID: "c1",
		GuildID:   "g1",
		Author:    &discordgo.User{ID: "u1"},
		Content:   "ping",
		Mentions: []*discordgo.User{
			{ID: "u2"}, {ID: "u3"}, {ID: "u4"}, {ID: "u5"}, {ID: "u6"},
		},
	}}

	if _, flagged, detail := module.HandleMessage(context.Background(), &discordgo.Session{}, msg, "g1", true); !flagged {
		t.Fatalf("expected mention burst flag")
	} else if detail == "" {
		t.Fatalf("expected detail for mention burst")
	}
}
