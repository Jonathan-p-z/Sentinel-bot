package bot

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentinel-adaptive/internal/analytics"
	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/antihate"
	"sentinel-adaptive/internal/modules/antinuke"
	"sentinel-adaptive/internal/modules/antiphishing"
	"sentinel-adaptive/internal/modules/antiraid"
	"sentinel-adaptive/internal/modules/antispam"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/modules/behavior"
	"sentinel-adaptive/internal/modules/verification"
	"sentinel-adaptive/internal/playbook"
	"sentinel-adaptive/internal/risk"
	"sentinel-adaptive/internal/storage"
	"sentinel-adaptive/internal/trust"

	"github.com/bwmarrin/discordgo"
	"go.uber.org/zap"
)

type Bot struct {
	cfg            config.Config
	logger         *zap.Logger
	store          *storage.Store
	risk           *risk.Engine
	trust          *trust.Engine
	playbook       *playbook.Engine
	audit          *audit.Logger
	analytics      *analytics.Service
	session        *discordgo.Session
	antispam       *antispam.Module
	antihate       *antihate.Module
	antiraid       *antiraid.Module
	antiphish      *antiphishing.Module
	antinuke       *antinuke.Module
	antinukeExempt *antinuke.Module
	behavior       *behavior.Module
	verify         *verification.Module
	auditAgg       map[string]*auditAggregate
	auditAggMu     sync.Mutex
	warnAgg        map[string]*warningAggregate
	warnAggMu      sync.Mutex
	detectAgg      map[string]*detectionAggregate
	detectAggMu    sync.Mutex
	lockdownMu     sync.Mutex
	lockdownMap    map[string]*lockdownSnapshot
	discordAggMu   sync.Mutex
	discordAgg     map[string]*discordEventAggregate
	warnSeen       map[string]time.Time
	digestLastSent map[string]time.Time
	alertStates    map[string]alertState
	incidentCtx    map[string]incidentContext
}

type alertState struct {
	previousSeverity string
	lastAlertTime    time.Time
}

type incidentContext struct {
	incidentType string
	rule         string
	value        string
	threshold    string
	updatedAt    time.Time
}

type auditAggregate struct {
	channelID string
	messageID string
	count     int
	lastAt    time.Time
}

type warningAggregate struct {
	channelID string
	messageID string
	count     int
	lastAt    time.Time
}

type detectionAggregate struct {
	channelID string
	messageID string
	count     int
	lastAt    time.Time
	lastInfo  string
}

type discordEventAggregate struct {
	channelID string
	messageID string
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	lastSent  time.Time
}

type lockdownSnapshot struct {
	channels map[string]channelSnapshot
}

type channelSnapshot struct {
	slowmode int
	allow    int64
	deny     int64
	hasPerm  bool
}

func New(cfg config.Config, logger *zap.Logger, store *storage.Store, riskEngine *risk.Engine, trustEngine *trust.Engine, playbookEngine *playbook.Engine, auditLogger *audit.Logger, analyticsEngine *analytics.Service) (*Bot, error) {
	session, err := discordgo.New("Bot " + cfg.DiscordToken)
	if err != nil {
		return nil, err
	}

	session.Identify.Intents = discordgo.IntentsGuilds |
		discordgo.IntentsGuildMessages |
		discordgo.IntentsGuildMembers |
		discordgo.IntentsGuildBans |
		discordgo.IntentsMessageContent |
		discordgo.IntentsGuildVoiceStates

	b := &Bot{
		cfg:            cfg,
		logger:         logger,
		store:          store,
		risk:           riskEngine,
		trust:          trustEngine,
		playbook:       playbookEngine,
		audit:          auditLogger,
		analytics:      analyticsEngine,
		session:        session,
		auditAgg:       make(map[string]*auditAggregate),
		warnAgg:        make(map[string]*warningAggregate),
		detectAgg:      make(map[string]*detectionAggregate),
		lockdownMap:    make(map[string]*lockdownSnapshot),
		discordAgg:     make(map[string]*discordEventAggregate),
		warnSeen:       make(map[string]time.Time),
		digestLastSent: make(map[string]time.Time),
		alertStates:    make(map[string]alertState),
		incidentCtx:    make(map[string]incidentContext),
	}

	b.antispam = antispam.New(cfg.Thresholds, riskEngine, auditLogger)
	b.antihate = antihate.New(antihate.Config{
		Enabled:           cfg.Hate.Enabled,
		Patterns:          cfg.Hate.Patterns,
		Allowlist:         cfg.Hate.Allowlist,
		TimeoutMinutes:    cfg.Hate.TimeoutMinutes,
		ForgiveAfterDays:  cfg.Hate.ForgiveAfterDays,
		DeleteInAuditMode: cfg.Hate.DeleteInAuditMode,
	}, store, auditLogger)
	b.antiraid = antiraid.New(cfg.Thresholds, playbookEngine, auditLogger)
	b.antiphish = antiphishing.New(riskEngine, auditLogger)
	b.antinuke = antinuke.New(time.Duration(cfg.Nuke.WindowSeconds) * time.Second)
	b.antinukeExempt = antinuke.New(time.Duration(cfg.Nuke.ExemptWindowSeconds) * time.Second)
	b.behavior = behavior.New()
	b.verify = verification.New()
	if b.audit != nil {
		b.audit.SetNotifier(func(ctx context.Context, entry storage.AuditLog) {
			if !b.cfg.Notifications.AuditToChannel {
				return
			}
			b.notifyAudit(ctx, entry)
		})
	}

	return b, nil
}

func (b *Bot) Start() error {
	b.session.AddHandler(b.onReady)
	b.session.AddHandler(b.onMessageCreate)
	b.session.AddHandler(b.onGuildMemberAdd)
	b.session.AddHandler(b.onChannelCreate)
	b.session.AddHandler(b.onChannelDelete)
	b.session.AddHandler(b.onChannelUpdate)
	b.session.AddHandler(b.onRoleCreate)
	b.session.AddHandler(b.onRoleDelete)
	b.session.AddHandler(b.onRoleUpdate)
	b.session.AddHandler(b.onWebhooksUpdate)
	b.session.AddHandler(b.onGuildBanAdd)
	b.session.AddHandler(b.onGuildUpdate)
	b.session.AddHandler(b.onInteractionCreate)

	if err := b.session.Open(); err != nil {
		return err
	}

	if err := b.registerCommands(); err != nil {
		return err
	}

	b.startDailySummary()

	return nil
}

func (b *Bot) Close(ctx context.Context) {
	_ = ctx
	if b.session != nil {
		_ = b.session.Close()
	}
}

func (b *Bot) onReady(session *discordgo.Session, event *discordgo.Ready) {
	b.logger.Info("discord ready", zap.String("user", session.State.User.Username))
	ctx := context.Background()
	for _, guild := range event.Guilds {
		if guild == nil || guild.ID == "" {
			continue
		}
		b.ensureGuildDefaults(ctx, guild.ID)
	}
}

func (b *Bot) onMessageCreate(session *discordgo.Session, msg *discordgo.MessageCreate) {
	if msg.Author == nil || msg.Author.Bot {
		return
	}
	if msg.GuildID == "" {
		return
	}

	ctx := context.Background()
	settings := b.guildSettings(ctx, msg.GuildID)
	auditOnly := b.isAuditMode(settings)
	if settings.AntiHateEnabled && !b.isWhitelisted(ctx, msg.GuildID, msg.Author.ID) {
		result := b.antihate.HandleMessage(ctx, session, msg, msg.GuildID, auditOnly)
		if result.Matched {
			if result.Err != nil {
				b.audit.Log(ctx, audit.LevelWarn, msg.GuildID, msg.Author.ID, "action_failed", "anti_hate persistence failed")
			}
			return
		}
	}

	allowlist, blocklist := b.getDomainLists(ctx, msg.GuildID)
	if _, flagged, detail := b.antiphish.HandleMessage(ctx, session, msg, msg.GuildID, allowlist, blocklist, settings.PhishingRisk, auditOnly); flagged {
		count := b.handlePhishingDetection(ctx, msg.GuildID, msg.Author.ID, detail, auditOnly)
		threshold := b.phishingThreshold()
		if count >= threshold {
			score := b.risk.AddRisk(msg.GuildID, msg.Author.ID, b.phishingBanDelta())
			b.applyRiskActions(ctx, msg.GuildID, msg.Author.ID, score, auditOnly)
		}
		return
	}

	if score, flagged := b.antispam.HandleMessage(ctx, session, msg, msg.GuildID, auditOnly); flagged {
		b.applyRiskActions(ctx, msg.GuildID, msg.Author.ID, score, auditOnly)
		return
	}

	b.behavior.HandleMessage(ctx)
	b.trust.Increase(msg.GuildID, msg.Author.ID, 0.5)
}

func (b *Bot) onGuildMemberAdd(session *discordgo.Session, event *discordgo.GuildMemberAdd) {
	if event.GuildID == "" {
		return
	}
	ctx := context.Background()
	_ = session
	if b.antiraid.HandleJoin(ctx, session, event) {
		b.enterLockdown(ctx, event.GuildID, "anti_raid")
	}
}

func (b *Bot) onChannelCreate(session *discordgo.Session, event *discordgo.ChannelCreate) {
	if event.Channel == nil || event.Channel.GuildID == "" {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.Channel.GuildID, discordgo.AuditLogActionChannelCreate, event.Channel.ID)
	b.handleNukeAction(ctx, event.Channel.GuildID, actorID, "channel_create", event.Channel.ID)
}

func (b *Bot) onChannelDelete(session *discordgo.Session, event *discordgo.ChannelDelete) {
	if event.Channel == nil || event.Channel.GuildID == "" {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.Channel.GuildID, discordgo.AuditLogActionChannelDelete, event.Channel.ID)
	b.handleNukeAction(ctx, event.Channel.GuildID, actorID, "channel_delete", event.Channel.ID)
}

func (b *Bot) onChannelUpdate(session *discordgo.Session, event *discordgo.ChannelUpdate) {
	if event.Channel == nil || event.Channel.GuildID == "" {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.Channel.GuildID, discordgo.AuditLogActionChannelUpdate, event.Channel.ID)
	b.handleNukeAction(ctx, event.Channel.GuildID, actorID, "channel_update", event.Channel.ID)
}

func (b *Bot) onRoleCreate(session *discordgo.Session, event *discordgo.GuildRoleCreate) {
	if event.GuildID == "" || event.Role == nil {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.GuildID, discordgo.AuditLogActionRoleCreate, event.Role.ID)
	b.handleNukeAction(ctx, event.GuildID, actorID, "role_create", event.Role.ID)
}

func (b *Bot) onRoleDelete(session *discordgo.Session, event *discordgo.GuildRoleDelete) {
	if event.GuildID == "" || event.RoleID == "" {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.GuildID, discordgo.AuditLogActionRoleDelete, event.RoleID)
	b.handleNukeAction(ctx, event.GuildID, actorID, "role_delete", event.RoleID)
}

func (b *Bot) onRoleUpdate(session *discordgo.Session, event *discordgo.GuildRoleUpdate) {
	if event.GuildID == "" || event.Role == nil {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.GuildID, discordgo.AuditLogActionRoleUpdate, event.Role.ID)
	b.handleNukeAction(ctx, event.GuildID, actorID, "role_update", event.Role.ID)
}

func (b *Bot) onWebhooksUpdate(session *discordgo.Session, event *discordgo.WebhooksUpdate) {
	if event.GuildID == "" {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.GuildID, discordgo.AuditLogActionWebhookUpdate, event.ChannelID)
	b.handleNukeAction(ctx, event.GuildID, actorID, "webhook_update", event.ChannelID)
}

func (b *Bot) onGuildBanAdd(session *discordgo.Session, event *discordgo.GuildBanAdd) {
	if event.GuildID == "" || event.User == nil {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.GuildID, discordgo.AuditLogActionMemberBanAdd, event.User.ID)
	b.handleNukeAction(ctx, event.GuildID, actorID, "ban_add", event.User.ID)
}

func (b *Bot) onGuildUpdate(session *discordgo.Session, event *discordgo.GuildUpdate) {
	if event.Guild == nil || event.Guild.ID == "" {
		return
	}
	ctx := context.Background()
	actorID := b.resolveAuditActor(event.Guild.ID, discordgo.AuditLogActionGuildUpdate, event.Guild.ID)
	b.handleNukeAction(ctx, event.Guild.ID, actorID, "guild_update", event.Guild.ID)
}

func (b *Bot) handleNukeAction(ctx context.Context, guildID, actorID, action, targetID string) {
	settings := b.guildSettings(ctx, guildID)
	if !settings.NukeEnabled {
		return
	}
	threshold := b.nukeThreshold(settings, action)
	if threshold <= 0 {
		return
	}
	if actorID == "" {
		return
	}
	if b.isWhitelisted(ctx, guildID, actorID) {
		exemptThreshold := b.cfg.Nuke.ExemptThreshold
		if exemptThreshold <= 0 {
			return
		}
		exemptWindow := time.Duration(b.cfg.Nuke.ExemptWindowSeconds) * time.Second
		if exemptWindow <= 0 {
			exemptWindow = 10 * time.Second
		}
		b.antinukeExempt.SetWindow(exemptWindow)
		count := b.antinukeExempt.Count(guildID, actorID, action)
		if count != exemptThreshold {
			return
		}
		detail := fmt.Sprintf("type=NUKE rule=%s/%ds value=%d/%ds threshold=%d action=%s target=%s exempt=true", action, b.cfg.Nuke.ExemptWindowSeconds, count, b.cfg.Nuke.ExemptWindowSeconds, exemptThreshold, action, targetID)
		b.audit.Log(ctx, audit.LevelCrit, guildID, actorID, "anti_nuke", detail)
		b.enterLockdown(ctx, guildID, "anti_nuke_exempt")
		return
	}
	window := time.Duration(settings.NukeWindowSeconds) * time.Second
	if window <= 0 {
		window = 20 * time.Second
	}
	b.antinuke.SetWindow(window)
	count := b.antinuke.Count(guildID, actorID, action)
	if count != threshold {
		return
	}

	detail := fmt.Sprintf("type=NUKE rule=%s/%ds value=%d/%ds threshold=%d action=%s target=%s", action, settings.NukeWindowSeconds, count, settings.NukeWindowSeconds, threshold, action, targetID)
	b.audit.Log(ctx, audit.LevelCrit, guildID, actorID, "anti_nuke", detail)
	b.enterLockdown(ctx, guildID, "anti_nuke")
	b.applyNukeSanction(ctx, guildID, actorID)
}

func (b *Bot) nukeThreshold(settings storage.GuildSettings, action string) int {
	switch action {
	case "channel_delete":
		return settings.NukeChannelDelete
	case "channel_create":
		return settings.NukeChannelCreate
	case "channel_update":
		return settings.NukeChannelUpdate
	case "role_delete":
		return settings.NukeRoleDelete
	case "role_create":
		return settings.NukeRoleCreate
	case "role_update":
		return settings.NukeRoleUpdate
	case "webhook_update":
		return settings.NukeWebhookUpdate
	case "ban_add":
		return settings.NukeBanAdd
	case "guild_update":
		return settings.NukeGuildUpdate
	default:
		return 0
	}
}

func (b *Bot) resolveAuditActor(guildID string, actionType discordgo.AuditLogAction, targetID string) string {
	logs, err := b.session.GuildAuditLog(guildID, "", "", int(actionType), 5)
	if err != nil || logs == nil {
		return ""
	}
	for _, entry := range logs.AuditLogEntries {
		if entry == nil {
			continue
		}
		if targetID != "" && entry.TargetID != targetID {
			continue
		}
		ts, err := discordgo.SnowflakeTimestamp(entry.ID)
		if err == nil && time.Since(ts) > 30*time.Second {
			continue
		}
		return entry.UserID
	}
	return ""
}

func (b *Bot) applyNukeSanction(ctx context.Context, guildID, userID string) {
	if userID == "" {
		return
	}
	if !b.cfg.Actions.Enabled {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "enforcement_disabled", "nuke sanction blocked")
		return
	}
	minutes := b.cfg.Actions.TimeoutMinutes
	if minutes <= 0 {
		minutes = 10
	}
	until := time.Now().Add(time.Duration(minutes) * time.Minute)
	if err := b.session.GuildMemberTimeout(guildID, userID, &until); err != nil {
		b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", "nuke timeout failed")
		return
	}
	b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "nuke_timeout", fmt.Sprintf("minutes=%d", minutes))
}

func (b *Bot) enterLockdown(ctx context.Context, guildID, reason string) bool {
	if b.playbook == nil {
		return false
	}
	if !b.playbook.TriggerLockdown(ctx, guildID) {
		return false
	}
	applied := b.applyLockdown(ctx, guildID)
	if !applied {
		return true
	}

	lockdownMinutes := b.cfg.Playbook.LockdownMinutes
	if lockdownMinutes <= 0 {
		lockdownMinutes = 10
	}
	go func() {
		time.Sleep(time.Duration(lockdownMinutes) * time.Minute)
		b.restoreLockdown(context.Background(), guildID, reason)
	}()
	return true
}

func (b *Bot) applyLockdown(ctx context.Context, guildID string) bool {
	settings := b.guildSettings(ctx, guildID)
	b.lockdownMu.Lock()
	if _, exists := b.lockdownMap[guildID]; exists {
		b.lockdownMu.Unlock()
		return false
	}
	b.lockdownMu.Unlock()
	channels, err := b.session.GuildChannels(guildID)
	if err != nil {
		return false
	}

	snapshot := &lockdownSnapshot{channels: make(map[string]channelSnapshot)}
	for _, channel := range channels {
		if channel == nil {
			continue
		}
		if channel.Type != discordgo.ChannelTypeGuildText && channel.Type != discordgo.ChannelTypeGuildNews {
			continue
		}
		snap := channelSnapshot{slowmode: channel.RateLimitPerUser}
		for _, overwrite := range channel.PermissionOverwrites {
			if overwrite.Type == discordgo.PermissionOverwriteTypeRole && overwrite.ID == guildID {
				snap.allow = overwrite.Allow
				snap.deny = overwrite.Deny
				snap.hasPerm = true
				break
			}
		}
		snapshot.channels[channel.ID] = snap

		if b.cfg.Playbook.LockdownDenySend {
			allow := snap.allow
			deny := snap.deny | discordgo.PermissionSendMessages
			_ = b.session.ChannelPermissionSet(channel.ID, guildID, discordgo.PermissionOverwriteTypeRole, allow, deny)
		}
		if b.cfg.Playbook.LockdownSlowmode > 0 && channel.RateLimitPerUser != b.cfg.Playbook.LockdownSlowmode {
			slowmode := b.cfg.Playbook.LockdownSlowmode
			_, _ = b.session.ChannelEditComplex(channel.ID, &discordgo.ChannelEdit{RateLimitPerUser: &slowmode})
		}
	}

	b.lockdownMu.Lock()
	b.lockdownMap[guildID] = snapshot
	b.lockdownMu.Unlock()

	settings.LockdownEnabled = true
	_ = b.store.UpsertGuildSettings(ctx, settings)
	return true
}

func (b *Bot) restoreLockdown(ctx context.Context, guildID, reason string) {
	b.lockdownMu.Lock()
	snapshot := b.lockdownMap[guildID]
	if snapshot != nil {
		delete(b.lockdownMap, guildID)
	}
	b.lockdownMu.Unlock()
	if snapshot == nil {
		settings := b.guildSettings(ctx, guildID)
		if settings.LockdownEnabled {
			settings.LockdownEnabled = false
			_ = b.store.UpsertGuildSettings(ctx, settings)
		}
		_ = reason
		return
	}

	for channelID, snap := range snapshot.channels {
		if snap.hasPerm {
			_ = b.session.ChannelPermissionSet(channelID, guildID, discordgo.PermissionOverwriteTypeRole, snap.allow, snap.deny)
		} else {
			_ = b.session.ChannelPermissionDelete(channelID, guildID)
		}
		slowmode := snap.slowmode
		_, _ = b.session.ChannelEditComplex(channelID, &discordgo.ChannelEdit{RateLimitPerUser: &slowmode})
	}

	settings := b.guildSettings(ctx, guildID)
	if settings.LockdownEnabled {
		settings.LockdownEnabled = false
		_ = b.store.UpsertGuildSettings(ctx, settings)
	}
	_ = reason
}

func (b *Bot) isWhitelisted(ctx context.Context, guildID, userID string) bool {
	if userID == "" {
		return false
	}
	if b.session == nil {
		return false
	}
	guild, err := b.session.State.Guild(guildID)
	if err != nil || guild == nil {
		guild, _ = b.session.Guild(guildID)
	}
	if guild != nil && guild.OwnerID == userID {
		return true
	}

	member := b.memberForUser(guildID, userID)
	if member != nil && guild != nil && b.memberHasAdmin(guild, member) {
		return true
	}

	users, err := b.store.ListWhitelistUsers(ctx, guildID)
	if err == nil {
		for _, id := range users {
			if id == userID {
				return true
			}
		}
	}
	if member == nil {
		return false
	}
	roles, err := b.store.ListWhitelistRoles(ctx, guildID)
	if err != nil {
		return false
	}
	roleSet := make(map[string]struct{}, len(roles))
	for _, id := range roles {
		roleSet[id] = struct{}{}
	}
	for _, roleID := range member.Roles {
		if _, ok := roleSet[roleID]; ok {
			return true
		}
	}
	return false
}

func (b *Bot) memberForUser(guildID, userID string) *discordgo.Member {
	member, err := b.session.State.Member(guildID, userID)
	if err == nil && member != nil {
		return member
	}
	member, _ = b.session.GuildMember(guildID, userID)
	return member
}

func (b *Bot) memberHasAdmin(guild *discordgo.Guild, member *discordgo.Member) bool {
	if guild == nil || member == nil {
		return false
	}
	perms := int64(0)
	for _, role := range guild.Roles {
		if role.ID == guild.ID {
			perms |= role.Permissions
			break
		}
	}
	roleMap := make(map[string]*discordgo.Role, len(guild.Roles))
	for _, role := range guild.Roles {
		roleMap[role.ID] = role
	}
	for _, roleID := range member.Roles {
		if role := roleMap[roleID]; role != nil {
			perms |= role.Permissions
		}
	}
	return perms&discordgo.PermissionAdministrator != 0
}

func (b *Bot) applyRiskActions(ctx context.Context, guildID, userID string, score float64, auditOnly bool) {
	settings := b.guildSettings(ctx, guildID)
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	trustScore := b.trust.GetScore(guildID, userID)
	effective := b.risk.EffectiveScore(score, trustScore)

	actions := b.cfg.Actions
	action := ""
	level := audit.LevelInfo

	switch {
	case effective >= actions.Ban:
		action = "ban"
		level = audit.LevelCrit
	case effective >= actions.Timeout:
		action = "timeout"
		level = audit.LevelHigh
	case effective >= actions.Quarantine:
		action = "quarantine"
		level = audit.LevelHigh
	case effective >= actions.Delete:
		action = "delete"
		level = audit.LevelInfo
	default:
		return
	}

	reason := fmt.Sprintf("action=%s effective=%.1f risk=%.1f trust=%.1f mode=%s", action, effective, score, trustScore, settings.Mode)
	b.audit.Log(ctx, level, guildID, userID, "risk_action", reason)

	if auditOnly {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "audit_mode", "sanction simulated")
		return
	}

	if !actions.Enabled {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "enforcement_disabled", "actions disabled")
		return
	}

	switch action {
	case "ban":
		if err := b.session.GuildBanCreateWithReason(guildID, userID, "Sentinel Adaptive risk ban", 0); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", "ban failed")
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_ban_failed"), err))
		}
	case "timeout":
		minutes := actions.TimeoutMinutes
		if minutes <= 0 {
			minutes = 10
		}
		until := time.Now().Add(time.Duration(minutes) * time.Minute)
		if err := b.session.GuildMemberTimeout(guildID, userID, &until); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", "timeout failed")
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_timeout_failed"), err))
		}
	case "quarantine":
		if actions.QuarantineRoleID == "" {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", "quarantine role not set")
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_quarantine_role_missing"), nil))
			return
		}
		if err := b.session.GuildMemberRoleAdd(guildID, userID, actions.QuarantineRoleID); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", "quarantine role add failed")
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_quarantine_failed"), err))
		}
	case "delete":
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "action_skipped", "delete requires message context")
		b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_delete_requires_context"), nil))
	}
}

func (b *Bot) sendSecurityEmbed(ctx context.Context, guildID string, embed *discordgo.MessageEmbed) {
	_ = ctx
	settings := b.guildSettings(ctx, guildID)
	channelID := settings.SecurityLogChannel
	if channelID == "" {
		channelID = b.cfg.DefaultSecurityLogChannel
	}
	if channelID == "" || embed == nil {
		return
	}
	_, _ = b.session.ChannelMessageSendEmbed(channelID, embed)
}

func (b *Bot) warnUser(userID string, embed *discordgo.MessageEmbed) {
	if userID == "" || embed == nil || !b.cfg.Notifications.DMWarnEnabled {
		return
	}
	channel, err := b.session.UserChannelCreate(userID)
	if err != nil {
		return
	}
	_, _ = b.session.ChannelMessageSendEmbed(channel.ID, embed)
}

func (b *Bot) sendChannelWarning(ctx context.Context, guildID, userID, action string, riskScore, trustScore, effective float64, auditOnly bool) {
	if !b.cfg.Notifications.ChannelWarnEnabled {
		return
	}
	settings := b.guildSettings(ctx, guildID)
	channelID := settings.SecurityLogChannel
	if channelID == "" {
		channelID = b.cfg.DefaultSecurityLogChannel
	}
	if channelID == "" {
		return
	}
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	key := guildID + "|" + userID + "|" + action
	if auditOnly {
		key += "|audit"
	}
	window := 10 * time.Minute

	b.warnAggMu.Lock()
	agg := b.warnAgg[key]
	if agg != nil && agg.channelID == channelID && time.Since(agg.lastAt) <= window {
		agg.count++
		agg.lastAt = time.Now()
		count := agg.count
		messageID := agg.messageID
		b.warnAggMu.Unlock()
		embed := b.buildChannelWarningEmbed(lang, userID, action, riskScore, trustScore, effective, auditOnly, count)
		if _, err := b.session.ChannelMessageEditEmbed(channelID, messageID, embed); err == nil {
			return
		}
		b.warnAggMu.Lock()
		delete(b.warnAgg, key)
		b.warnAggMu.Unlock()
	}
	b.warnAggMu.Unlock()

	embed := b.buildChannelWarningEmbed(lang, userID, action, riskScore, trustScore, effective, auditOnly, 1)
	msg, err := b.session.ChannelMessageSendEmbed(channelID, embed)
	if err != nil || msg == nil {
		return
	}
	b.warnAggMu.Lock()
	b.warnAgg[key] = &warningAggregate{channelID: channelID, messageID: msg.ID, count: 1, lastAt: time.Now()}
	b.warnAggMu.Unlock()
}

func (b *Bot) buildActionEmbed(lang, userID, action string, riskScore, trustScore, effective float64, auditOnly bool) *discordgo.MessageEmbed {
	mode := "normal"
	if auditOnly {
		mode = "audit"
	}
	severity := b.severityLabel(lang, action)
	if severity == "" {
		severity = b.t(lang, "severity_info")
	}

	return &discordgo.MessageEmbed{
		Title:       "🚨 " + b.t(lang, "action_title"),
		Description: b.t(lang, "action_desc"),
		Color:       b.cfg.Notifications.EmbedColors.Action,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
			{Name: b.t(lang, "field_action"), Value: b.actionLabel(lang, action), Inline: true},
			{Name: b.t(lang, "field_mode"), Value: b.modeLabel(lang, mode), Inline: true},
			{Name: b.t(lang, "field_severity"), Value: severity, Inline: true},
			{Name: b.t(lang, "field_risk"), Value: fmt.Sprintf("%.1f", riskScore), Inline: true},
			{Name: b.t(lang, "field_trust"), Value: fmt.Sprintf("%.1f", trustScore), Inline: true},
			{Name: b.t(lang, "field_effective"), Value: fmt.Sprintf("%.1f", effective), Inline: true},
		},
	}
}

func (b *Bot) buildUserWarningEmbed(lang, action string, riskScore, trustScore, effective float64, auditOnly bool) *discordgo.MessageEmbed {
	note := b.t(lang, "status_applied")
	if auditOnly {
		note = b.t(lang, "status_audit")
	}
	mode := "normal"
	if auditOnly {
		mode = "audit"
	}
	severity := b.severityLabel(lang, action)
	if severity == "" {
		severity = b.t(lang, "severity_info")
	}

	return &discordgo.MessageEmbed{
		Title:       b.t(lang, "warning_title"),
		Description: b.t(lang, "warning_desc"),
		Color:       b.cfg.Notifications.EmbedColors.Warning,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: b.t(lang, "field_action"), Value: b.actionLabel(lang, action), Inline: true},
			{Name: b.t(lang, "field_status"), Value: note, Inline: true},
			{Name: b.t(lang, "field_mode"), Value: b.modeLabel(lang, mode), Inline: true},
			{Name: b.t(lang, "field_severity"), Value: severity, Inline: true},
			{Name: b.t(lang, "field_risk"), Value: fmt.Sprintf("%.1f", riskScore), Inline: true},
			{Name: b.t(lang, "field_trust"), Value: fmt.Sprintf("%.1f", trustScore), Inline: true},
			{Name: b.t(lang, "field_effective"), Value: fmt.Sprintf("%.1f", effective), Inline: true},
		},
	}
}

func (b *Bot) buildChannelWarningEmbed(lang, userID, action string, riskScore, trustScore, effective float64, auditOnly bool, count int) *discordgo.MessageEmbed {
	mode := "normal"
	if auditOnly {
		mode = "audit"
	}
	status := b.t(lang, "status_applied")
	if auditOnly {
		status = b.t(lang, "status_audit")
	}
	severity := b.severityLabel(lang, action)
	if severity == "" {
		severity = b.t(lang, "severity_info")
	}
	fields := []*discordgo.MessageEmbedField{
		{Name: b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
		{Name: b.t(lang, "field_action"), Value: b.actionLabel(lang, action), Inline: true},
		{Name: b.t(lang, "field_mode"), Value: b.modeLabel(lang, mode), Inline: true},
		{Name: b.t(lang, "field_status"), Value: status, Inline: true},
		{Name: b.t(lang, "field_severity"), Value: severity, Inline: true},
	}
	if count > 1 {
		fields = append(fields, &discordgo.MessageEmbedField{Name: b.t(lang, "field_count"), Value: fmt.Sprintf("%d", count), Inline: true})
	}
	fields = append(fields,
		&discordgo.MessageEmbedField{Name: b.t(lang, "field_risk"), Value: fmt.Sprintf("%.1f", riskScore), Inline: true},
		&discordgo.MessageEmbedField{Name: b.t(lang, "field_trust"), Value: fmt.Sprintf("%.1f", trustScore), Inline: true},
		&discordgo.MessageEmbedField{Name: b.t(lang, "field_effective"), Value: fmt.Sprintf("%.1f", effective), Inline: true},
	)

	return &discordgo.MessageEmbed{
		Title:       "⚠️ " + b.t(lang, "warning_title"),
		Description: b.t(lang, "warning_desc_channel"),
		Color:       b.cfg.Notifications.EmbedColors.Warning,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields:      fields,
	}
}

func (b *Bot) handlePhishingDetection(ctx context.Context, guildID, userID, detail string, auditOnly bool) int {
	_ = ctx
	_ = auditOnly
	window := b.phishingWindow()
	key := guildID + "|" + userID + "|phishing"

	b.detectAggMu.Lock()
	agg := b.detectAgg[key]
	if agg != nil && time.Since(agg.lastAt) <= window {
		agg.count++
		agg.lastAt = time.Now()
		agg.lastInfo = detail
	} else {
		agg = &detectionAggregate{count: 1, lastAt: time.Now(), lastInfo: detail}
		b.detectAgg[key] = agg
	}
	count := agg.count
	b.detectAggMu.Unlock()
	return count
}

func (b *Bot) buildDetectionWarningEmbed(lang, userID, detail string, count, threshold int, auditOnly bool) *discordgo.MessageEmbed {
	mode := "normal"
	if auditOnly {
		mode = "audit"
	}
	fields := []*discordgo.MessageEmbedField{
		{Name: b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
		{Name: b.t(lang, "field_mode"), Value: b.modeLabel(lang, mode), Inline: true},
		{Name: b.t(lang, "field_count"), Value: fmt.Sprintf("%d/%d", count, threshold), Inline: true},
	}
	if detail != "" {
		fields = append(fields, &discordgo.MessageEmbedField{Name: b.t(lang, "field_reason"), Value: detail, Inline: false})
	}

	return &discordgo.MessageEmbed{
		Title:       b.t(lang, "warning_phishing_title"),
		Description: b.t(lang, "warning_phishing_desc"),
		Color:       b.cfg.Notifications.EmbedColors.Warning,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields:      fields,
	}
}

func (b *Bot) phishingThreshold() int {
	if b.cfg.Thresholds.BurstLinks > 0 {
		return b.cfg.Thresholds.BurstLinks
	}
	return 3
}

func (b *Bot) phishingWindow() time.Duration {
	seconds := b.cfg.Thresholds.BurstWindowSeconds
	if seconds <= 0 {
		seconds = 60
	}
	return time.Duration(seconds) * time.Second
}

func (b *Bot) phishingBanDelta() float64 {
	ban := b.cfg.Actions.Ban
	if ban <= 0 {
		ban = 80
	}
	trustHeadroom := b.cfg.Trust.MaxScore * b.cfg.Risk.TrustWeight
	return ban + trustHeadroom + 1
}

func (b *Bot) buildErrorEmbed(lang, userID, reason string, err error) *discordgo.MessageEmbed {
	message := reason
	if err != nil {
		message = reason + ": " + err.Error()
	}
	return &discordgo.MessageEmbed{
		Title:       b.t(lang, "error_title"),
		Description: message,
		Color:       b.cfg.Notifications.EmbedColors.Error,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
		},
	}
}

func (b *Bot) buildAuditEmbed(lang string, entry storage.AuditLog, count int) *discordgo.MessageEmbed {
	_ = count
	values := b.parseAuditDetailsMap(entry.Details)
	severity := strings.ToUpper(strings.TrimSpace(entry.Level))
	if severity == "" {
		severity = audit.LevelInfo
	}
	emoji := "⚠️"
	if severity == audit.LevelHigh || severity == audit.LevelCrit || severity == "CRITICAL" {
		emoji = "🚨"
	}

	stateKey := entry.GuildID + "|" + entry.UserID
	b.discordAggMu.Lock()
	ctx, hasCtx := b.incidentCtx[stateKey]
	b.discordAggMu.Unlock()

	incidentType := strings.ToUpper(strings.TrimSpace(values["type"]))
	rule := strings.TrimSpace(values["rule"])
	current := strings.TrimSpace(values["value"])
	threshold := strings.TrimSpace(values["threshold"])
	if (!hasCtx || time.Since(ctx.updatedAt) > 10*time.Minute) && entry.Event != "risk_action" {
		incidentType, rule, current, threshold = b.extractIncidentDetails(entry)
	} else if entry.Event == "risk_action" && hasCtx {
		if incidentType == "" {
			incidentType = ctx.incidentType
		}
		if rule == "" {
			rule = ctx.rule
		}
		if current == "" {
			current = ctx.value
		}
		if threshold == "" {
			threshold = ctx.threshold
		}
	}
	if incidentType == "" {
		incidentType = "RISK"
	}
	if rule == "" {
		rule = "-"
	}
	if current == "" {
		current = "-"
	}
	if threshold == "" {
		threshold = "-"
	}

	riskValue := strings.TrimSpace(values["risk"])
	trustValue := strings.TrimSpace(values["trust"])
	effectiveValue := strings.TrimSpace(values["effective"])
	modeValue := strings.TrimSpace(values["mode"])
	if modeValue == "" {
		modeValue = "normal"
	}
	if riskValue == "" && entry.UserID != "" {
		riskValue = fmt.Sprintf("%.1f", b.risk.GetScore(entry.GuildID, entry.UserID))
	}
	if trustValue == "" && entry.UserID != "" {
		trustValue = fmt.Sprintf("%.1f", b.trust.GetScore(entry.GuildID, entry.UserID))
	}
	if riskValue == "" {
		riskValue = "0.0"
	}
	if trustValue == "" {
		trustValue = "0.0"
	}
	if effectiveValue == "" {
		riskFloat, _ := strconv.ParseFloat(riskValue, 64)
		trustFloat, _ := strconv.ParseFloat(trustValue, 64)
		effectiveValue = fmt.Sprintf("%.1f", b.risk.EffectiveScore(riskFloat, trustFloat))
	}

	summary := "Incident de securite detecte"
	if entry.Event == "risk_action" {
		actionText := "Action automatique"
		switch values["action"] {
		case "delete":
			actionText = "Suppression automatique"
		case "timeout":
			actionText = "Timeout automatique"
		case "quarantine":
			actionText = "Quarantaine automatique"
		case "ban":
			actionText = "Ban automatique"
		}
		target := "@" + b.t(lang, "value_system")
		if entry.UserID != "" {
			target = "<@" + entry.UserID + ">"
		}
		summary = actionText + " appliquee a " + target
	}

	footerID := entry.EventID
	if footerID == "" {
		footerID = "N/A"
	}

	return &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("%s SECURITY INCIDENT — %s", emoji, severity),
		Description: fmt.Sprintf("%s\nScore effectif: %s\n\nType: %s\nRegle: %s\nValeur: %s\nSeuil: %s", summary, effectiveValue, incidentType, rule, current, threshold),
		Color:       b.cfg.Notifications.EmbedColors.Action,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Risk", Value: riskValue, Inline: true},
			{Name: "Trust", Value: trustValue, Inline: true},
			{Name: "Mode", Value: b.modeLabel(lang, modeValue), Inline: true},
		},
		Footer: &discordgo.MessageEmbedFooter{Text: "Event ID: " + footerID},
	}
}

func (b *Bot) parseAuditDetailsMap(details string) map[string]string {
	parts := strings.Fields(details)
	values := make(map[string]string, len(parts))
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		values[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return values
}

func (b *Bot) auditEventLabel(lang, event string) string {
	switch event {
	case "anti_phishing":
		return b.t(lang, "event_anti_phishing")
	case "anti_spam":
		return b.t(lang, "event_anti_spam")
	case "anti_raid":
		return b.t(lang, "event_anti_raid")
	case "anti_hate":
		return b.t(lang, "event_anti_hate")
	case "risk_action":
		return b.t(lang, "event_risk_action")
	case "enforcement_disabled":
		return b.t(lang, "event_enforcement_disabled")
	case "action_failed":
		return b.t(lang, "event_action_failed")
	case "action_skipped":
		return b.t(lang, "event_action_skipped")
	case "audit_mode":
		return b.t(lang, "event_audit_mode")
	case "raid_lockdown":
		return b.t(lang, "event_raid_lockdown")
	case "risk_reset":
		return b.t(lang, "event_risk_reset")
	case "test":
		return b.t(lang, "event_test")
	case "security":
		return b.t(lang, "event_security")
	case "anti_nuke":
		return b.t(lang, "event_anti_nuke")
	case "nuke_timeout":
		return b.t(lang, "event_nuke_timeout")
	default:
		return event
	}
}

func (b *Bot) formatAuditDetails(lang string, entry storage.AuditLog) string {
	if entry.Details == "" {
		return entry.Details
	}

	switch entry.Event {
	case "anti_phishing":
		if strings.HasPrefix(entry.Details, "suspicious link: ") {
			url := strings.TrimPrefix(entry.Details, "suspicious link: ")
			return b.t(lang, "label_url") + ": " + url
		}
	case "anti_spam":
		return b.t(lang, "label_cause") + ": " + b.t(lang, "cause_spam_burst")
	case "anti_raid":
		return b.t(lang, "label_cause") + ": " + b.t(lang, "cause_raid_burst")
	case "enforcement_disabled":
		return b.t(lang, "label_status") + ": " + b.t(lang, "status_enforcement_disabled")
	case "audit_mode":
		return b.t(lang, "label_status") + ": " + b.t(lang, "status_audit")
	case "action_failed":
		return b.t(lang, "label_status") + ": " + entry.Details
	case "action_skipped":
		return b.t(lang, "label_note") + ": " + entry.Details
	case "risk_action":
		parts := strings.Fields(entry.Details)
		data := make(map[string]string, len(parts))
		for _, part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				continue
			}
			data[kv[0]] = kv[1]
		}
		if len(data) == 0 {
			return entry.Details
		}
		lines := []string{}
		if value, ok := data["action"]; ok {
			lines = append(lines, b.t(lang, "label_action")+": "+b.actionLabel(lang, value))
		}
		if value, ok := data["mode"]; ok {
			lines = append(lines, b.t(lang, "field_mode")+": "+b.modeLabel(lang, value))
		}
		if value, ok := data["risk"]; ok {
			lines = append(lines, b.t(lang, "field_risk")+": "+value)
		}
		if value, ok := data["trust"]; ok {
			lines = append(lines, b.t(lang, "field_trust")+": "+value)
		}
		if value, ok := data["effective"]; ok {
			lines = append(lines, b.t(lang, "field_effective")+": "+value)
		}
		if len(lines) == 0 {
			return entry.Details
		}
		return strings.Join(lines, "\n")
	}

	return entry.Details
}

func (b *Bot) notifyAudit(ctx context.Context, entry storage.AuditLog) {
	settings := b.guildSettings(ctx, entry.GuildID)
	channelID := b.alertsChannelID(settings)
	if channelID == "" {
		return
	}
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}
	b.updateIncidentContext(entry)
	if !b.shouldSendDiscordEvent(settings, entry) {
		return
	}

	severity := strings.ToUpper(strings.TrimSpace(entry.Level))
	if severity == "" {
		severity = audit.LevelInfo
	}
	stateKey := entry.GuildID + "|" + entry.UserID
	if !b.shouldAlertState(stateKey, severity, b.settingsAlertCooldownMinutes(settings)) {
		return
	}

	embed := b.buildAuditEmbed(lang, entry, 1)
	if embed == nil {
		return
	}
	_, _ = b.session.ChannelMessageSendEmbed(channelID, embed)
}

func (b *Bot) shouldSendDiscordEvent(settings storage.GuildSettings, entry storage.AuditLog) bool {
	level := strings.ToUpper(strings.TrimSpace(entry.Level))
	if level == audit.LevelInfo {
		return false
	}
	if b.levelRank(level) < b.levelRank(b.settingsDiscordMinLevel(settings)) {
		return false
	}
	if !b.isCategoryAllowed(settings, entry.Event) {
		return false
	}
	return level == audit.LevelWarn || level == audit.LevelHigh || level == audit.LevelCrit || level == "CRITICAL"
}

func (b *Bot) shouldAlertState(stateKey, severity string, cooldownMinutes int) bool {
	now := time.Now()
	cooldown := time.Duration(cooldownMinutes) * time.Minute
	if cooldown <= 0 {
		cooldown = 10 * time.Minute
	}
	b.discordAggMu.Lock()
	defer b.discordAggMu.Unlock()
	state := b.alertStates[stateKey]
	if state.previousSeverity == "" || state.previousSeverity != severity {
		b.alertStates[stateKey] = alertState{previousSeverity: severity, lastAlertTime: now}
		return true
	}
	if now.Sub(state.lastAlertTime) >= cooldown {
		b.alertStates[stateKey] = alertState{previousSeverity: severity, lastAlertTime: now}
		return true
	}
	return false
}

func (b *Bot) settingsAlertCooldownMinutes(settings storage.GuildSettings) int {
	_ = settings
	if b.cfg.Log.AlertCooldownMinutes > 0 {
		return b.cfg.Log.AlertCooldownMinutes
	}
	return 10
}

func (b *Bot) updateIncidentContext(entry storage.AuditLog) {
	incidentType, rule, value, threshold := b.extractIncidentDetails(entry)
	if incidentType == "" {
		return
	}
	key := entry.GuildID + "|" + entry.UserID
	b.discordAggMu.Lock()
	b.incidentCtx[key] = incidentContext{
		incidentType: incidentType,
		rule:         rule,
		value:        value,
		threshold:    threshold,
		updatedAt:    time.Now(),
	}
	b.discordAggMu.Unlock()
}

func (b *Bot) extractIncidentDetails(entry storage.AuditLog) (string, string, string, string) {
	values := b.parseAuditDetailsMap(entry.Details)
	incidentType := strings.ToUpper(strings.TrimSpace(values["type"]))
	rule := strings.TrimSpace(values["rule"])
	value := strings.TrimSpace(values["value"])
	threshold := strings.TrimSpace(values["threshold"])
	if incidentType != "" {
		return incidentType, rule, value, threshold
	}
	switch entry.Event {
	case "anti_spam":
		return "SPAM", rule, value, threshold
	case "anti_phishing":
		return "PHISHING", rule, value, threshold
	case "anti_raid":
		return "RAID", rule, value, threshold
	case "anti_hate":
		return "HATE_SPEECH", rule, value, threshold
	case "anti_nuke", "nuke_timeout":
		return "NUKE", rule, value, threshold
	default:
		return "", "", "", ""
	}
}

func (b *Bot) levelRank(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case audit.LevelInfo:
		return 1
	case audit.LevelWarn:
		return 2
	case audit.LevelHigh:
		return 3
	case audit.LevelCrit, "CRITICAL":
		return 4
	default:
		return 1
	}
}

func (b *Bot) settingsDiscordMinLevel(settings storage.GuildSettings) string {
	value := strings.ToUpper(strings.TrimSpace(settings.DiscordMinLevel))
	if value == "" {
		value = strings.ToUpper(strings.TrimSpace(b.cfg.Log.DiscordMinLevel))
	}
	if value == "" {
		return audit.LevelHigh
	}
	return value
}

func (b *Bot) settingsDedupWindowSeconds(settings storage.GuildSettings) int {
	if settings.DedupWindowSeconds > 0 {
		return settings.DedupWindowSeconds
	}
	if b.cfg.Log.DedupWindowSeconds > 0 {
		return b.cfg.Log.DedupWindowSeconds
	}
	return 60
}

func (b *Bot) settingsDiscordRateLimitSeconds(settings storage.GuildSettings) int {
	if settings.DiscordRateLimit > 0 {
		return settings.DiscordRateLimit
	}
	if b.cfg.Log.DiscordRateLimitSec > 0 {
		return b.cfg.Log.DiscordRateLimitSec
	}
	return 10
}

func (b *Bot) settingsWarnRareMinutes(settings storage.GuildSettings) int {
	if settings.WarnRareMinutes > 0 {
		return settings.WarnRareMinutes
	}
	if b.cfg.Log.WarnRareMinutes > 0 {
		return b.cfg.Log.WarnRareMinutes
	}
	return 60
}

func (b *Bot) isCategoryAllowed(settings storage.GuildSettings, event string) bool {
	allowed := map[string]struct{}{}
	raw := strings.TrimSpace(settings.DiscordCategories)
	if raw == "" {
		raw = strings.Join(b.cfg.Log.DiscordCategories, ",")
	}
	if raw == "" {
		return true
	}
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(strings.ToLower(part))
		if value != "" {
			allowed[value] = struct{}{}
		}
	}
	_, ok := allowed[strings.ToLower(strings.TrimSpace(event))]
	return ok
}

func (b *Bot) alertsChannelID(settings storage.GuildSettings) string {
	if settings.SecurityLogChannel != "" {
		return settings.SecurityLogChannel
	}
	return b.cfg.DefaultSecurityLogChannel
}

func (b *Bot) auditChannelID(settings storage.GuildSettings) string {
	if settings.AuditLogChannel != "" {
		return settings.AuditLogChannel
	}
	if b.cfg.DefaultAuditLogChannel != "" {
		return b.cfg.DefaultAuditLogChannel
	}
	return b.alertsChannelID(settings)
}

func (b *Bot) buildAuditDigestEmbed(lang string, entry storage.AuditLog, count int, window time.Duration) *discordgo.MessageEmbed {
	base := b.buildAuditEmbed(lang, entry, count)
	if base == nil {
		return nil
	}
	desc := fmt.Sprintf("%s\nEvent #%s", b.t(lang, "audit_desc"), entry.EventID)
	if count > 1 {
		desc = fmt.Sprintf("%s\nEvent #%s — %d occurrences in %ds", b.t(lang, "audit_desc"), entry.EventID, count, int(window.Seconds()))
	}
	base.Description = desc
	return base
}

func (b *Bot) startDailySummary() {
	if !b.cfg.Notifications.DailySummary && b.cfg.Log.DigestIntervalMinutes <= 0 {
		return
	}
	go func() {
		time.Sleep(30 * time.Second)
		b.sendConfiguredDigests()
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			b.sendConfiguredDigests()
		}
	}()
}

func (b *Bot) sendConfiguredDigests() {
	if b.session == nil || b.session.State == nil {
		return
	}
	ctx := context.Background()
	now := time.Now()
	for _, guild := range b.session.State.Guilds {
		if guild == nil {
			continue
		}
		settings := b.guildSettings(ctx, guild.ID)
		channelID := b.auditChannelID(settings)
		if channelID == "" {
			continue
		}
		intervalMinutes := settings.DigestIntervalMin
		if intervalMinutes <= 0 {
			intervalMinutes = b.cfg.Log.DigestIntervalMinutes
		}
		if intervalMinutes <= 0 {
			intervalMinutes = 15
		}
		interval := time.Duration(intervalMinutes) * time.Minute
		last := b.digestLastSent[guild.ID]
		if !last.IsZero() && now.Sub(last) < interval {
			continue
		}
		lang := settings.Language
		if lang == "" {
			lang = b.cfg.DefaultLanguage
		}
		embed := b.buildDigestSummaryEmbed(ctx, lang, guild.ID, interval)
		if embed == nil {
			continue
		}
		if _, err := b.session.ChannelMessageSendEmbed(channelID, embed); err == nil {
			b.digestLastSent[guild.ID] = now
		}
	}
}

func (b *Bot) buildDigestSummaryEmbed(ctx context.Context, lang, guildID string, interval time.Duration) *discordgo.MessageEmbed {
	since := time.Now().Add(-interval)
	logs, err := b.store.ListAuditLogs(ctx, guildID, since)
	if err != nil {
		return nil
	}
	riskLines := b.buildRiskSummaryLines(lang, guildID, 10)
	phishingCount := 0
	lockdownCount := 0
	timeoutCount := 0
	banCount := 0
	domains := map[string]int{}

	for _, entry := range logs {
		switch entry.Event {
		case "anti_phishing":
			phishingCount++
			if strings.HasPrefix(entry.Details, "suspicious link: ") {
				raw := strings.TrimSpace(strings.TrimPrefix(entry.Details, "suspicious link: "))
				if parsed, parseErr := url.Parse(raw); parseErr == nil {
					host := strings.ToLower(parsed.Hostname())
					if host != "" {
						domains[host]++
					}
				}
			}
		case "anti_raid", "raid_lockdown", "anti_nuke":
			lockdownCount++
		case "nuke_timeout":
			timeoutCount++
		case "risk_action":
			if strings.Contains(entry.Details, "action=timeout") {
				timeoutCount++
			}
			if strings.Contains(entry.Details, "action=ban") {
				banCount++
			}
		}
	}

	blockedDomains := b.topBlockedDomains(domains, 5)
	if blockedDomains == "" {
		blockedDomains = b.t(lang, "value_none")
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: b.t(lang, "digest_field_top_risk"), Value: riskLines, Inline: false},
		{Name: b.t(lang, "digest_field_phishing"), Value: fmt.Sprintf("%d", phishingCount), Inline: true},
		{Name: b.t(lang, "digest_field_lockdowns"), Value: fmt.Sprintf("%d", lockdownCount), Inline: true},
		{Name: b.t(lang, "digest_field_sanctions"), Value: fmt.Sprintf("%d/%d", timeoutCount, banCount), Inline: true},
		{Name: b.t(lang, "digest_field_domains"), Value: blockedDomains, Inline: false},
	}

	return &discordgo.MessageEmbed{
		Title:       "📊 " + b.t(lang, "digest_title"),
		Description: fmt.Sprintf(b.t(lang, "digest_desc"), int(interval.Minutes())),
		Color:       b.cfg.Notifications.EmbedColors.Action,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields:      fields,
	}
}

func (b *Bot) topBlockedDomains(counts map[string]int, limit int) string {
	if len(counts) == 0 {
		return ""
	}
	type pair struct {
		domain string
		count  int
	}
	items := make([]pair, 0, len(counts))
	for domain, count := range counts {
		items = append(items, pair{domain: domain, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].domain < items[j].domain
		}
		return items[i].count > items[j].count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("%s (%d)", item.domain, item.count))
	}
	return strings.Join(lines, "\n")
}

func (b *Bot) buildDailySummaryEmbed(lang, guildID string) *discordgo.MessageEmbed {
	riskLines := b.buildRiskSummaryLines(lang, guildID, 5)
	voiceLines := b.buildVoiceSummaryLines(guildID, 5, 25)
	if voiceLines == "" {
		voiceLines = b.t(lang, "value_none")
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: b.t(lang, "field_risk_top"), Value: riskLines, Inline: false},
		{Name: b.t(lang, "field_voice"), Value: voiceLines, Inline: false},
	}

	return &discordgo.MessageEmbed{
		Title:       b.t(lang, "daily_summary_title"),
		Description: b.t(lang, "daily_summary_desc"),
		Color:       b.cfg.Notifications.EmbedColors.Action,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields:      fields,
	}
}

func (b *Bot) buildRiskSummaryLines(lang, guildID string, limit int) string {
	entries := b.risk.Top(guildID, limit)
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Score <= 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("<@%s> - %.1f", entry.UserID, entry.Score))
	}
	if len(lines) == 0 {
		return b.t(lang, "value_none")
	}
	return strings.Join(lines, "\n")
}

func (b *Bot) buildVoiceSummaryLines(guildID string, maxChannels, maxUsers int) string {
	if b.session == nil || b.session.State == nil {
		return ""
	}
	guild, err := b.session.State.Guild(guildID)
	if err != nil || guild == nil {
		return ""
	}

	channelUsers := make(map[string][]string)
	for _, state := range guild.VoiceStates {
		if state == nil || state.ChannelID == "" || state.UserID == "" {
			continue
		}
		channelUsers[state.ChannelID] = append(channelUsers[state.ChannelID], "<@"+state.UserID+">")
	}
	if len(channelUsers) == 0 {
		return ""
	}

	channels := make([]string, 0, len(channelUsers))
	for channelID := range channelUsers {
		channels = append(channels, channelID)
	}
	sort.Strings(channels)

	lines := []string{}
	for _, channelID := range channels {
		if maxChannels > 0 && len(lines) >= maxChannels {
			break
		}
		users := channelUsers[channelID]
		if maxUsers > 0 && len(users) > maxUsers {
			users = users[:maxUsers]
		}
		lines = append(lines, "<#"+channelID+">: "+strings.Join(users, ", "))
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}

func (b *Bot) embedAuthor(lang string) *discordgo.MessageEmbedAuthor {
	return &discordgo.MessageEmbedAuthor{Name: b.t(lang, "author_security")}
}

func (b *Bot) embedFooter(lang string) *discordgo.MessageEmbedFooter {
	return &discordgo.MessageEmbedFooter{Text: b.t(lang, "footer_brand")}
}

func (b *Bot) severityLabel(lang, action string) string {
	switch action {
	case "ban":
		return b.t(lang, "severity_crit")
	case "timeout", "quarantine":
		return b.t(lang, "severity_warn")
	case "delete":
		return b.t(lang, "severity_info")
	default:
		return ""
	}
}

func (b *Bot) modeLabel(lang, mode string) string {
	if mode == "audit" {
		return b.t(lang, "mode_audit")
	}
	return b.t(lang, "mode_normal")
}

func (b *Bot) actionLabel(lang, action string) string {
	switch action {
	case "ban":
		return b.t(lang, "action_ban")
	case "timeout":
		return b.t(lang, "action_timeout")
	case "quarantine":
		return b.t(lang, "action_quarantine")
	case "delete":
		return b.t(lang, "action_delete")
	default:
		return action
	}
}

func (b *Bot) guildSettings(ctx context.Context, guildID string) storage.GuildSettings {
	defaults := storage.GuildSettings{
		GuildID:            guildID,
		SecurityLogChannel: b.cfg.DefaultSecurityLogChannel,
		AuditLogChannel:    b.cfg.DefaultAuditLogChannel,
		Language:           b.cfg.DefaultLanguage,
		Mode:               b.cfg.Mode,
		RulePreset:         b.cfg.RulePreset,
		RetentionDays:      b.cfg.RetentionDays,
		DiscordMinLevel:    b.cfg.Log.DiscordMinLevel,
		DiscordCategories:  strings.Join(b.cfg.Log.DiscordCategories, ","),
		DiscordRateLimit:   b.cfg.Log.DiscordRateLimitSec,
		DigestIntervalMin:  b.cfg.Log.DigestIntervalMinutes,
		WarnRareMinutes:    b.cfg.Log.WarnRareMinutes,
		DedupWindowSeconds: b.cfg.Log.DedupWindowSeconds,
		SpamMessages:       b.cfg.Thresholds.SpamMessages,
		SpamWindowSeconds:  b.cfg.Thresholds.SpamWindowSeconds,
		RaidJoins:          b.cfg.Thresholds.RaidJoins,
		RaidWindowSeconds:  b.cfg.Thresholds.RaidWindowSeconds,
		PhishingRisk:       b.cfg.Thresholds.PhishingRisk,
		LockdownEnabled:    false,
		AntiHateEnabled:    b.cfg.Hate.Enabled,
		NukeEnabled:        b.cfg.Nuke.Enabled,
		NukeWindowSeconds:  b.cfg.Nuke.WindowSeconds,
		NukeChannelDelete:  b.cfg.Nuke.ChannelDelete,
		NukeChannelCreate:  b.cfg.Nuke.ChannelCreate,
		NukeChannelUpdate:  b.cfg.Nuke.ChannelUpdate,
		NukeRoleDelete:     b.cfg.Nuke.RoleDelete,
		NukeRoleCreate:     b.cfg.Nuke.RoleCreate,
		NukeRoleUpdate:     b.cfg.Nuke.RoleUpdate,
		NukeWebhookUpdate:  b.cfg.Nuke.WebhookUpdate,
		NukeBanAdd:         b.cfg.Nuke.BanAdd,
		NukeGuildUpdate:    b.cfg.Nuke.GuildUpdate,
	}

	settings, err := b.store.GetGuildSettings(ctx, guildID, defaults)
	if err != nil {
		b.logger.Warn("guild settings fallback", zap.Error(err))
		return defaults
	}
	return settings
}

func (b *Bot) ensureGuildDefaults(ctx context.Context, guildID string) {
	settings := b.guildSettings(ctx, guildID)
	settings.GuildID = guildID
	if err := b.store.UpsertGuildSettings(ctx, settings); err != nil {
		b.logger.Warn("guild defaults upsert failed", zap.String("guild_id", guildID), zap.Error(err))
	}
}

func (b *Bot) isAuditMode(settings storage.GuildSettings) bool {
	return settings.Mode == "audit"
}

func (b *Bot) getDomainLists(ctx context.Context, guildID string) (map[string]struct{}, map[string]struct{}) {
	allowlist := make(map[string]struct{})
	blocklist := make(map[string]struct{})

	allow, err := b.store.ListDomainAllow(ctx, guildID)
	if err == nil {
		for _, domain := range allow {
			allowlist[domain] = struct{}{}
		}
	}
	block, err := b.store.ListDomainBlock(ctx, guildID)
	if err == nil {
		for _, domain := range block {
			blocklist[domain] = struct{}{}
		}
	}
	return allowlist, blocklist
}

func (b *Bot) respond(session *discordgo.Session, interaction *discordgo.InteractionCreate, content string, ephemeral bool) {
	flags := discordgo.MessageFlags(0)
	if ephemeral {
		flags = discordgo.MessageFlagsEphemeral
	}
	_ = session.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: content,
			Flags:   flags,
		},
	})
}

func (b *Bot) respondEmbed(session *discordgo.Session, interaction *discordgo.InteractionCreate, embed *discordgo.MessageEmbed, ephemeral bool) {
	if embed == nil {
		b.respond(session, interaction, "No response available.", ephemeral)
		return
	}
	flags := discordgo.MessageFlags(0)
	if ephemeral {
		flags = discordgo.MessageFlagsEphemeral
	}
	_ = session.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
			Flags:  flags,
		},
	})
}

func (b *Bot) auditToChannel(ctx context.Context, guildID, message string) {
	settings := b.guildSettings(ctx, guildID)
	channelID := b.auditChannelID(settings)
	if channelID == "" {
		return
	}
	_, _ = b.session.ChannelMessageSend(channelID, message)
}

func formatReport(report analytics.Report) string {
	return fmt.Sprintf("Total: %d | INFO: %d | WARN: %d | HIGH: %d | CRIT: %d", report.Total, report.ByLevel[audit.LevelInfo], report.ByLevel[audit.LevelWarn], report.ByLevel[audit.LevelHigh], report.ByLevel[audit.LevelCrit])
}
