package antiraid

import (
	"context"
	"strconv"
	"testing"
	"time"

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
	if module.HandleJoin(ctx, session, join) {
		t.Fatalf("did not expect trigger on first join")
	}
	if module.HandleJoin(ctx, session, join) {
		t.Fatalf("did not expect trigger on second join")
	}
	if !module.HandleJoin(ctx, session, join) {
		t.Fatalf("expected anti-raid trigger")
	}
}

func TestRaidNewAccountsBurst(t *testing.T) {
	store, _ := storage.New(":memory:")
	_ = store.Migrate()
	auditLogger := audit.NewLogger(store, zap.NewNop())
	playbookEngine := playbook.New(playbook.Config{LockdownMinutes: 1, StrictModeMinutes: 1, ExitStepSeconds: 1}, auditLogger)
	module := New(config.Thresholds{RaidJoins: 4, RaidWindowSeconds: 10}, playbookEngine, auditLogger)

	session := &discordgo.Session{}
	ctx := context.Background()
	now := time.Now()

	join1 := &discordgo.GuildMemberAdd{Member: &discordgo.Member{GuildID: "g1", User: &discordgo.User{ID: snowflakeFromTime(now.Add(-time.Hour))}}}
	if module.HandleJoin(ctx, session, join1) {
		t.Fatalf("did not expect trigger on first new account join")
	}
	join2 := &discordgo.GuildMemberAdd{Member: &discordgo.Member{GuildID: "g1", User: &discordgo.User{ID: snowflakeFromTime(now.Add(-2 * time.Hour))}}}
	if !module.HandleJoin(ctx, session, join2) {
		t.Fatalf("expected trigger on burst of new accounts")
	}
}

func snowflakeFromTime(ts time.Time) string {
	const discordEpochMillis = int64(1420070400000)
	millis := ts.UnixMilli()
	if millis < discordEpochMillis {
		millis = discordEpochMillis
	}
	value := (millis - discordEpochMillis) << 22
	return strconv.FormatInt(value, 10)
}
