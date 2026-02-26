package antiraid

import (
	"context"
	"testing"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/playbook"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
	"go.uber.org/zap"
)

func TestRaidJoinCounter(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	auditLogger := audit.NewLogger(store, zap.NewNop())
	playbookEngine := playbook.New(playbook.Config{LockdownMinutes: 1, StrictModeMinutes: 1, ExitStepSeconds: 1}, auditLogger)
	module := New(config.Thresholds{RaidJoins: 3, RaidWindowSeconds: 5}, playbookEngine, auditLogger)

	session := &discordgo.Session{}
	ctx := context.Background()

	join := &discordgo.GuildMemberAdd{Member: &discordgo.Member{GuildID: "g1", User: &discordgo.User{ID: "u1"}}}
	module.HandleJoin(ctx, session, join)
	module.HandleJoin(ctx, session, join)
	module.HandleJoin(ctx, session, join)
	state := playbookEngine.IsLockdown("g1")
	if !state.Lockdown {
		t.Fatalf("expected lockdown")
	}
}
