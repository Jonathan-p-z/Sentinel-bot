package bot

import (
	"context"
	"fmt"
	"sort"
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
	cfg              config.Config
	logger           *zap.Logger
	store            *storage.Store
	risk             *risk.Engine
	trust            *trust.Engine
	playbook         *playbook.Engine
	audit            *audit.Logger
	analytics        *analytics.Service
	session          *discordgo.Session
	antispam         *antispam.Module
	antihate         *antihate.Module
	antiraid         *antiraid.Module
	antiphish        *antiphishing.Module
	antinuke         *antinuke.Module
	antinukeExempt   *antinuke.Module
	behavior         *behavior.Module
	verify           *verification.Module
	rootCtx          context.Context
	rootCancel       context.CancelFunc
	auditAgg         map[string]*auditAggregate
	auditAggMu       sync.Mutex
	warnAgg          map[string]*warningAggregate
	warnAggMu        sync.Mutex
	detectAgg        map[string]*detectionAggregate
	detectAggMu      sync.Mutex
	riskActionAgg    map[string]*riskActionAggregate
	riskActionMu     sync.Mutex
	modWarns         map[string]int
	modWarnsMu       sync.Mutex
	antiHateWarns    map[string]int
	antiHateWarnsMu  sync.Mutex
	lockdownMu       sync.Mutex
	lockdownMap      map[string]*lockdownSnapshot
	whitelistCacheMu sync.Mutex
	whitelistCache   map[string]*whitelistCacheEntry
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

type riskActionAggregate struct {
	lastAt time.Time
}

type whitelistCacheEntry struct {
	users     []string
	roles     []string
	fetchedAt time.Time
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

	rootCtx, rootCancel := context.WithCancel(context.Background())

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
		rootCtx:        rootCtx,
		rootCancel:     rootCancel,
		auditAgg:       make(map[string]*auditAggregate),
		warnAgg:        make(map[string]*warningAggregate),
		detectAgg:      make(map[string]*detectionAggregate),
		riskActionAgg:  make(map[string]*riskActionAggregate),
		modWarns:       make(map[string]int),
		antiHateWarns:  make(map[string]int),
		lockdownMap:    make(map[string]*lockdownSnapshot),
		whitelistCache: make(map[string]*whitelistCacheEntry),
	}

	b.antispam = antispam.New(cfg.Thresholds, riskEngine, auditLogger)
	b.antihate = antihate.New(riskEngine, auditLogger)
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
	b.session.AddHandler(b.onGuildBanRemove)
	b.session.AddHandler(b.onGuildUpdate)
	b.session.AddHandler(b.onInteractionCreate)

	if err := b.session.Open(); err != nil {
		return err
	}

	if err := b.registerCommands(); err != nil {
		return err
	}

	b.startDailySummary()
	b.startCleanup()

	return nil
}

func (b *Bot) Close(ctx context.Context) {
	_ = ctx
	if b.rootCancel != nil {
		b.rootCancel()
	}
	if b.session != nil {
		_ = b.session.Close()
	}
}

func (b *Bot) onReady(session *discordgo.Session, event *discordgo.Ready) {
	b.logger.Info("discord ready", zap.String("user", session.State.User.Username))
}

func (b *Bot) onMessageCreate(session *discordgo.Session, msg *discordgo.MessageCreate) {
	if msg.Author == nil || msg.Author.Bot {
		return
	}
	if msg.GuildID == "" {
		return
	}
	if b.userIsAboveBot(msg.GuildID, msg.Author.ID) {
		return
	}

	ctx := context.Background()
	settings := b.guildSettings(ctx, msg.GuildID)
	auditOnly := b.isAuditMode(settings)

	allowlist, blocklist := b.getDomainLists(ctx, msg.GuildID)
	messageContext := antiphishing.MessageContext{}
	if channel, err := session.State.Channel(msg.ChannelID); err == nil && channel != nil {
		messageContext.ChannelType = channel.Type
	} else if channel, err := session.Channel(msg.ChannelID); err == nil && channel != nil {
		messageContext.ChannelType = channel.Type
	}
	if _, flagged, detail := b.antiphish.HandleMessage(ctx, session, msg, msg.GuildID, allowlist, blocklist, settings.PhishingRisk, auditOnly, messageContext); flagged {
		count := b.handlePhishingDetection(ctx, msg.GuildID, msg.Author.ID, detail, auditOnly)
		threshold := b.phishingThreshold()
		if count >= threshold {
			score := b.risk.AddRisk(msg.GuildID, msg.Author.ID, b.phishingBanDelta())
			b.applyRiskActions(ctx, msg.GuildID, msg.Author.ID, score, auditOnly, detail)
		}
		return
	}

	if score, flagged, detail := b.antihate.HandleMessage(ctx, session, msg, msg.GuildID, auditOnly); flagged {
		b.applyAntiHateActions(ctx, msg.GuildID, msg.Author.ID, score, auditOnly, detail)
		return
	}

	if !b.isSpamBypassChannel(session, msg.ChannelID) {
		if score, flagged, detail := b.antispam.HandleMessage(ctx, session, msg, msg.GuildID, auditOnly); flagged {
			b.applyRiskActions(ctx, msg.GuildID, msg.Author.ID, score, auditOnly, detail)
			return
		}
	}

	b.behavior.HandleMessage(ctx)
	b.trust.Increase(msg.GuildID, msg.Author.ID, 0.5)
}

func (b *Bot) isSpamBypassChannel(session *discordgo.Session, channelID string) bool {
	if channelID == "" {
		return false
	}

	if session != nil && session.State != nil {
		if channel, err := session.State.Channel(channelID); err == nil && channel != nil {
			return strings.EqualFold(channel.Name, "𝐒𝐏𝐀𝐌🗯️")
		}
	}

	if session == nil {
		return false
	}
	channel, err := session.Channel(channelID)
	if err != nil || channel == nil {
		return false
	}
	return strings.EqualFold(channel.Name, "𝐒𝐏𝐀𝐌🗯️")
}

func (b *Bot) onGuildMemberAdd(session *discordgo.Session, event *discordgo.GuildMemberAdd) {
	if event.GuildID == "" {
		return
	}
	ctx := context.Background()
	if event.Member != nil && event.Member.User != nil {
		userID := event.Member.User.ID
		if b.store != nil {
			if banReason, banned, err := b.store.GetBannedUserReason(ctx, event.GuildID, userID); err == nil && banned {
				if banReason == "discord_ban_event" {
					_ = b.store.RemoveBannedUser(ctx, event.GuildID, userID)
					b.audit.Log(ctx, audit.LevelInfo, event.GuildID, userID, "persistent_ban_skipped", fmt.Sprintf("user=<@%s> reason=%q stale_marker_removed=true", userID, banReason))
					return
				}
				reapplyReason := fmt.Sprintf("Sentinel persistent ban reapply: %s", banReason)
				if len(reapplyReason) > 512 {
					reapplyReason = reapplyReason[:512]
				}
				auditOnly := b.isAuditMode(b.guildSettings(ctx, event.GuildID))
				if auditOnly {
					b.audit.Log(ctx, audit.LevelInfo, event.GuildID, userID, "persistent_ban_skipped", fmt.Sprintf("user=<@%s> reason=%q audit_mode=true", userID, banReason))
					return
				}
				_ = b.session.GuildBanCreateWithReason(event.GuildID, userID, reapplyReason, 0)
				b.audit.Log(ctx, audit.LevelWarn, event.GuildID, userID, "persistent_ban_reapply", fmt.Sprintf("user=<@%s> ban_reason=%q rejoin_blocked=true", userID, banReason))
				return
			}
		}
	}
	_ = session
	if b.antiraid.HandleJoin(ctx, session, event) {
		b.enterLockdown(ctx, event.GuildID, "anti_raid")
		if event.Member != nil && event.Member.User != nil {
			b.applyRaidRestriction(ctx, event.GuildID, event.Member.User.ID)
		}
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
	if actorID != "" {
		score := b.risk.AddRisk(event.GuildID, actorID, 20)
		detail := fmt.Sprintf("user=<@%s> channel=%s score=%.1f", actorID, event.ChannelID, score)
		b.audit.Log(ctx, audit.LevelWarn, event.GuildID, actorID, "webhook_guard", detail)
		auditOnly := b.isAuditMode(b.guildSettings(ctx, event.GuildID))
		b.applyRiskActions(ctx, event.GuildID, actorID, score, auditOnly, "webhook update")
	}
}

func (b *Bot) addWarn(guildID, userID string) int {
	if guildID == "" || userID == "" {
		return 0
	}
	key := guildID + ":" + userID
	b.modWarnsMu.Lock()
	defer b.modWarnsMu.Unlock()
	b.modWarns[key]++
	return b.modWarns[key]
}

func (b *Bot) warnCount(guildID, userID string) int {
	if guildID == "" || userID == "" {
		return 0
	}
	key := guildID + ":" + userID
	b.modWarnsMu.Lock()
	defer b.modWarnsMu.Unlock()
	return b.modWarns[key]
}

func (b *Bot) addAntiHateWarn(ctx context.Context, guildID, userID string) int {
	if guildID == "" || userID == "" {
		return 0
	}
	if b.store != nil {
		if count, err := b.store.IncrementUserStrike(ctx, guildID, userID, "anti_hate"); err == nil {
			key := guildID + ":" + userID
			b.antiHateWarnsMu.Lock()
			b.antiHateWarns[key] = count
			b.antiHateWarnsMu.Unlock()
			return count
		}
	}
	key := guildID + ":" + userID
	b.antiHateWarnsMu.Lock()
	defer b.antiHateWarnsMu.Unlock()
	b.antiHateWarns[key]++
	return b.antiHateWarns[key]
}

type antiHateSanction struct {
	action         string
	timeoutMinutes int
	strike         int
}

func antiHateSanctionForStrike(strike int) antiHateSanction {
	timeoutSteps := []int{5, 15, 30, 60}
	idx := strike - 1
	if idx >= 0 && idx < len(timeoutSteps) {
		return antiHateSanction{action: "timeout", timeoutMinutes: timeoutSteps[idx], strike: strike}
	}
	return antiHateSanction{action: "ban", strike: strike}
}

func antiHateProgressText(lang string, strike int) string {
	if strike <= 0 {
		strike = 1
	}

	remainingTimeouts := 5 - strike
	remainingChances := 6 - strike
	if remainingTimeouts < 0 {
		remainingTimeouts = 0
	}
	if remainingChances < 0 {
		remainingChances = 0
	}

	if lang == "fr" {
		switch {
		case remainingChances == 0:
			return fmt.Sprintf("Infraction %d: ban definitif applique.", strike)
		case remainingTimeouts > 1:
			return fmt.Sprintf("Infraction %d: il te reste %d timeouts avant le ban definitif.", strike, remainingTimeouts)
		case remainingTimeouts == 1:
			return fmt.Sprintf("Infraction %d: il te reste 1 timeout avant le ban definitif.", strike)
		case remainingChances == 1:
			return fmt.Sprintf("Infraction %d: il te reste 1 seule chance avant le ban definitif.", strike)
		default:
			return fmt.Sprintf("Infraction %d: prochaine infraction = ban definitif.", strike)
		}
	}

	switch {
	case remainingChances == 0:
		return fmt.Sprintf("Strike %d: permanent ban applied.", strike)
	case remainingTimeouts > 1:
		return fmt.Sprintf("Strike %d: %d timeouts remain before a permanent ban.", strike, remainingTimeouts)
	case remainingTimeouts == 1:
		return fmt.Sprintf("Strike %d: 1 timeout remains before a permanent ban.", strike)
	case remainingChances == 1:
		return fmt.Sprintf("Strike %d: you have 1 last chance before a permanent ban.", strike)
	default:
		return fmt.Sprintf("Strike %d: next offense = permanent ban.", strike)
	}
}

func (b *Bot) onGuildBanAdd(session *discordgo.Session, event *discordgo.GuildBanAdd) {
	if event.GuildID == "" || event.User == nil {
		return
	}
	ctx := context.Background()
	if b.store != nil {
		if _, exists, err := b.store.GetBannedUserReason(ctx, event.GuildID, event.User.ID); err == nil {
			if !exists {
				_ = b.store.AddBannedUser(ctx, event.GuildID, event.User.ID, "discord_ban_event")
			}
		} else {
			b.audit.Log(ctx, audit.LevelWarn, event.GuildID, event.User.ID, "ban_persistence_lookup_failed", fmt.Sprintf("user=<@%s> error=%q", event.User.ID, err.Error()))
		}
	}
	actorID := b.resolveAuditActor(event.GuildID, discordgo.AuditLogActionMemberBanAdd, event.User.ID)
	b.handleNukeAction(ctx, event.GuildID, actorID, "ban_add", event.User.ID)
}

func (b *Bot) onGuildBanRemove(session *discordgo.Session, event *discordgo.GuildBanRemove) {
	if event.GuildID == "" || event.User == nil {
		return
	}
	_ = session

	ctx := context.Background()
	if b.store != nil {
		if err := b.store.RemoveBannedUser(ctx, event.GuildID, event.User.ID); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, event.GuildID, event.User.ID, "persistent_ban_remove_failed", fmt.Sprintf("user=<@%s> error=%q", event.User.ID, err.Error()))
		}
	}

	resetScore := b.cfg.Risk.MaxScore * 0.5
	if resetScore <= 0 {
		resetScore = 50
	}
	newScore := b.risk.SetScore(event.GuildID, event.User.ID, resetScore)
	b.audit.Log(ctx, audit.LevelInfo, event.GuildID, event.User.ID, "unban_risk_reset", fmt.Sprintf("user=<@%s> risk_score=%.1f reset_percent=50", event.User.ID, newScore))
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
		b.logger.Debug("nuke actor resolution failed, detection skipped",
			zap.String("guild_id", guildID),
			zap.String("action", action),
			zap.String("target_id", targetID),
		)
		return
	}
	if b.userIsAboveBot(guildID, actorID) {
		b.audit.Log(ctx, audit.LevelInfo, guildID, actorID, "nuke_ignored", fmt.Sprintf("user=<@%s> action=%s target=%s reason=actor_above_bot_hierarchy", actorID, action, targetID))
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
		totalCount := b.antinukeExempt.CountAny(guildID, actorID)
		exemptGlobalThreshold := exemptThreshold
		if exemptGlobalThreshold < 8 {
			exemptGlobalThreshold = 8
		}
		if count < exemptThreshold && totalCount < exemptGlobalThreshold {
			return
		}
		mode := "single"
		if totalCount >= exemptGlobalThreshold {
			mode = "multi"
		}
		detail := fmt.Sprintf("action=%s count=%d threshold=%d total=%d total_threshold=%d target=%s exempt=true mode=%s", action, count, exemptThreshold, totalCount, exemptGlobalThreshold, targetID, mode)
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
	totalCount := b.antinuke.CountAny(guildID, actorID)
	globalThreshold := threshold + 1
	if globalThreshold < 4 {
		globalThreshold = 4
	}
	if count < threshold && totalCount < globalThreshold {
		return
	}

	mode := "single"
	if totalCount >= globalThreshold {
		mode = "multi"
	}
	detail := fmt.Sprintf("action=%s count=%d threshold=%d total=%d total_threshold=%d target=%s mode=%s", action, count, threshold, totalCount, globalThreshold, targetID, mode)
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
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "enforcement_disabled", fmt.Sprintf("user=<@%s> action=ban source=nuke reason=actions_disabled", userID))
		return
	}
	b.banAndStore(ctx, guildID, userID, "anti_nuke_instant_ban")
}

func (b *Bot) banAndStore(ctx context.Context, guildID, userID, reason string) {
	if guildID == "" || userID == "" {
		return
	}
	if err := b.session.GuildBanCreateWithReason(guildID, userID, "Sentinel Adaptive enforcement", 0); err != nil {
		b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", fmt.Sprintf("user=<@%s> action=ban source=instant_ban error=%q", userID, err.Error()))
		return
	}
	if b.store != nil {
		_ = b.store.AddBannedUser(ctx, guildID, userID, reason)
	}
	b.audit.Log(ctx, audit.LevelCrit, guildID, userID, "instant_ban", reason)
}

func (b *Bot) applyRaidRestriction(ctx context.Context, guildID, userID string) {
	if guildID == "" || userID == "" {
		return
	}
	if b.userIsAboveBot(guildID, userID) {
		return
	}

	minutes := b.cfg.Actions.TimeoutMinutes
	if minutes <= 0 {
		minutes = 10
	}

	if !b.cfg.Actions.Enabled {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "enforcement_disabled", fmt.Sprintf("user=<@%s> action=timeout source=anti_raid reason=actions_disabled", userID))
		return
	}

	until := time.Now().Add(time.Duration(minutes) * time.Minute)
	if err := b.session.GuildMemberTimeout(guildID, userID, &until); err != nil {
		b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", fmt.Sprintf("user=<@%s> action=timeout source=anti_raid duration_minutes=%d error=%q", userID, minutes, err.Error()))
		return
	}
	b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "anti_raid_timeout", fmt.Sprintf("user=<@%s> duration_minutes=%d", userID, minutes))
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
		select {
		case <-time.After(time.Duration(lockdownMinutes) * time.Minute):
			b.restoreLockdown(b.rootCtx, guildID, reason)
		case <-b.rootCtx.Done():
			return
		}
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

	b.lockdownMap[guildID] = &lockdownSnapshot{channels: make(map[string]channelSnapshot)}
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

	const whitelistCacheTTL = 30 * time.Second
	b.whitelistCacheMu.Lock()
	entry := b.whitelistCache[guildID]
	if entry == nil || time.Since(entry.fetchedAt) > whitelistCacheTTL {
		users, _ := b.store.ListWhitelistUsers(ctx, guildID)
		roles, _ := b.store.ListWhitelistRoles(ctx, guildID)
		entry = &whitelistCacheEntry{users: users, roles: roles, fetchedAt: time.Now()}
		b.whitelistCache[guildID] = entry
	}
	users := entry.users
	roles := entry.roles
	b.whitelistCacheMu.Unlock()

	for _, id := range users {
		if id == userID {
			return true
		}
	}
	if member == nil {
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

func (b *Bot) invalidateWhitelistCache(guildID string) {
	b.whitelistCacheMu.Lock()
	delete(b.whitelistCache, guildID)
	b.whitelistCacheMu.Unlock()
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

func (b *Bot) userIsAboveBot(guildID, userID string) bool {
	if guildID == "" || userID == "" || b.session == nil {
		return false
	}

	guild, err := b.session.State.Guild(guildID)
	if err != nil || guild == nil {
		guild, _ = b.session.Guild(guildID)
	}
	if guild == nil {
		return false
	}
	if guild.OwnerID == userID {
		return true
	}

	botUserID := ""
	if b.session.State != nil && b.session.State.User != nil {
		botUserID = b.session.State.User.ID
	}
	if botUserID == "" {
		return false
	}

	targetMember := b.memberForUser(guildID, userID)
	botMember := b.memberForUser(guildID, botUserID)
	if targetMember == nil || botMember == nil {
		return false
	}

	targetPos := highestRolePosition(guild, targetMember)
	botPos := highestRolePosition(guild, botMember)
	return targetPos >= botPos
}

func highestRolePosition(guild *discordgo.Guild, member *discordgo.Member) int {
	if guild == nil || member == nil {
		return -1
	}
	roleMap := make(map[string]*discordgo.Role, len(guild.Roles))
	for _, role := range guild.Roles {
		roleMap[role.ID] = role
	}
	highest := -1
	for _, roleID := range member.Roles {
		if role := roleMap[roleID]; role != nil && role.Position > highest {
			highest = role.Position
		}
	}
	return highest
}

func (b *Bot) applyRiskActions(ctx context.Context, guildID, userID string, score float64, auditOnly bool, triggerDetail string) {
	if b.userIsAboveBot(guildID, userID) {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "risk_ignored", fmt.Sprintf("user=<@%s> reason=target_above_bot_hierarchy", userID))
		return
	}

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
		level = audit.LevelWarn
	case effective >= actions.Quarantine:
		action = "quarantine"
		level = audit.LevelWarn
	case effective >= actions.Delete:
		action = "delete"
		level = audit.LevelInfo
	default:
		return
	}

	if b.shouldSuppressRiskAction(guildID, userID, action, auditOnly) {
		return
	}

	reason := fmt.Sprintf("action=%s effective=%.1f risk=%.1f trust=%.1f mode=%s", action, effective, score, trustScore, settings.Mode)
	if triggerDetail != "" {
		reason += " trigger=" + triggerDetail
	}
	b.audit.Log(ctx, level, guildID, userID, "risk_action", reason)
	b.sendSecurityEmbed(ctx, guildID, b.buildActionEmbed(lang, userID, action, score, trustScore, effective, auditOnly))
	b.sendChannelWarning(ctx, guildID, userID, action, score, trustScore, effective, auditOnly)
	b.warnUser(userID, b.buildUserWarningEmbed(lang, action, score, trustScore, effective, auditOnly))

	if auditOnly {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "audit_mode", fmt.Sprintf("user=<@%s> action=%s simulated=true", userID, action))
		return
	}

	if !actions.Enabled {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "enforcement_disabled", fmt.Sprintf("user=<@%s> action=%s source=risk_action reason=actions_disabled", userID, action))
		return
	}

	switch action {
	case "ban":
		if err := b.session.GuildBanCreateWithReason(guildID, userID, "Sentinel Adaptive risk ban", 0); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", fmt.Sprintf("user=<@%s> action=ban source=risk_action error=%q", userID, err.Error()))
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_ban_failed"), err))
		}
	case "timeout":
		minutes := actions.TimeoutMinutes
		if minutes <= 0 {
			minutes = 10
		}
		until := time.Now().Add(time.Duration(minutes) * time.Minute)
		if err := b.session.GuildMemberTimeout(guildID, userID, &until); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", fmt.Sprintf("user=<@%s> action=timeout source=risk_action duration_minutes=%d error=%q", userID, minutes, err.Error()))
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_timeout_failed"), err))
		}
	case "quarantine":
		if actions.QuarantineRoleID == "" {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", fmt.Sprintf("user=<@%s> action=quarantine source=risk_action error=%q", userID, "quarantine role not set"))
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_quarantine_role_missing"), nil))
			return
		}
		if err := b.session.GuildMemberRoleAdd(guildID, userID, actions.QuarantineRoleID); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", fmt.Sprintf("user=<@%s> action=quarantine source=risk_action role_id=%s error=%q", userID, actions.QuarantineRoleID, err.Error()))
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_quarantine_failed"), err))
		}
	case "delete":
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "action_skipped", fmt.Sprintf("user=<@%s> action=delete reason=missing_message_context", userID))
		b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_delete_requires_context"), nil))
	}
}

func (b *Bot) applyAntiHateActions(ctx context.Context, guildID, userID string, score float64, auditOnly bool, triggerDetail string) {
	if b.userIsAboveBot(guildID, userID) {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "risk_ignored", fmt.Sprintf("user=<@%s> reason=target_above_bot_hierarchy", userID))
		return
	}

	settings := b.guildSettings(ctx, guildID)
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	strike := b.addAntiHateWarn(ctx, guildID, userID)
	sanction := antiHateSanctionForStrike(strike)
	trustScore := b.trust.GetScore(guildID, userID)
	effective := b.risk.EffectiveScore(score, trustScore)
	mode := settings.Mode
	if mode == "" {
		mode = b.cfg.Mode
	}

	reason := fmt.Sprintf("action=%s strike=%d effective=%.1f risk=%.1f trust=%.1f mode=%s", sanction.action, strike, effective, score, trustScore, mode)
	if sanction.timeoutMinutes > 0 {
		reason += fmt.Sprintf(" duration_minutes=%d", sanction.timeoutMinutes)
	}
	if triggerDetail != "" {
		reason += " trigger=" + triggerDetail
	}

	level := audit.LevelWarn
	if sanction.action == "ban" {
		level = audit.LevelCrit
	}

	b.audit.Log(ctx, level, guildID, userID, "anti_hate_enforcement", reason)
	b.sendSecurityEmbed(ctx, guildID, b.buildActionEmbed(lang, userID, sanction.action, score, trustScore, effective, auditOnly))
	b.sendChannelWarning(ctx, guildID, userID, sanction.action, score, trustScore, effective, auditOnly, b.antiHateWarningExtraField(lang, strike))
	b.warnUser(userID, b.buildAntiHateUserWarningEmbed(lang, sanction.action, score, trustScore, effective, auditOnly, strike))

	if auditOnly {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "audit_mode", fmt.Sprintf("user=<@%s> action=%s simulated=true source=anti_hate", userID, sanction.action))
		return
	}

	if sanction.action == "warn" {
		return
	}

	if !b.cfg.Actions.Enabled {
		b.audit.Log(ctx, audit.LevelInfo, guildID, userID, "enforcement_disabled", fmt.Sprintf("user=<@%s> action=%s source=anti_hate reason=actions_disabled", userID, sanction.action))
		return
	}

	switch sanction.action {
	case "timeout":
		until := time.Now().Add(time.Duration(sanction.timeoutMinutes) * time.Minute)
		if err := b.session.GuildMemberTimeout(guildID, userID, &until); err != nil {
			b.audit.Log(ctx, audit.LevelWarn, guildID, userID, "action_failed", fmt.Sprintf("user=<@%s> action=timeout source=anti_hate duration_minutes=%d error=%q", userID, sanction.timeoutMinutes, err.Error()))
			b.sendSecurityEmbed(ctx, guildID, b.buildErrorEmbed(lang, userID, b.t(lang, "action_timeout_failed"), err))
		}
	case "ban":
		b.banAndStore(ctx, guildID, userID, "anti_hate_repeat_offender")
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

func (b *Bot) sendChannelWarning(ctx context.Context, guildID, userID, action string, riskScore, trustScore, effective float64, auditOnly bool, extraFields ...*discordgo.MessageEmbedField) {
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
		embed := b.buildChannelWarningEmbed(lang, userID, action, riskScore, trustScore, effective, auditOnly, count, extraFields...)
		if _, err := b.session.ChannelMessageEditEmbed(channelID, messageID, embed); err == nil {
			return
		}
		b.warnAggMu.Lock()
		delete(b.warnAgg, key)
		b.warnAggMu.Unlock()
	} else {
		b.warnAggMu.Unlock()
	}

	embed := b.buildChannelWarningEmbed(lang, userID, action, riskScore, trustScore, effective, auditOnly, 1, extraFields...)
	msg, err := b.session.ChannelMessageSendEmbed(channelID, embed)
	if err != nil || msg == nil {
		return
	}
	b.warnAggMu.Lock()
	b.warnAgg[key] = &warningAggregate{channelID: channelID, messageID: msg.ID, count: 1, lastAt: time.Now()}
	b.warnAggMu.Unlock()
}

func (b *Bot) shouldSuppressRiskAction(guildID, userID, action string, auditOnly bool) bool {
	if guildID == "" || userID == "" || action == "" {
		return false
	}
	key := guildID + "|" + userID + "|" + action
	if auditOnly {
		key += "|audit"
	}
	window := 45 * time.Second

	b.riskActionMu.Lock()
	defer b.riskActionMu.Unlock()

	if agg := b.riskActionAgg[key]; agg != nil {
		if time.Since(agg.lastAt) <= window {
			agg.lastAt = time.Now()
			return true
		}
	}
	b.riskActionAgg[key] = &riskActionAggregate{lastAt: time.Now()}
	return false
}

// actionIcon returns an emoji representing the action type.
func (b *Bot) actionIcon(action string) string {
	switch action {
	case "ban":
		return "🔨"
	case "timeout":
		return "⏱️"
	case "quarantine":
		return "🔒"
	case "delete":
		return "🗑️"
	case "warn":
		return "⚠️"
	default:
		return "🛡️"
	}
}

// actionColor returns a color integer for a given action (red=ban, amber=timeout, yellow=warn).
func (b *Bot) actionColor(action string) int {
	switch action {
	case "ban":
		return 0xDC2626
	case "timeout":
		return 0xD97706
	case "quarantine":
		return 0x7C3AED
	case "delete":
		return 0xF97316
	case "warn":
		return 0xFBBF24
	default:
		return b.cfg.Notifications.EmbedColors.Action
	}
}

// levelColor returns a color integer for an audit log level.
func (b *Bot) levelColor(level string) int {
	switch level {
	case "crit":
		return 0xDC2626
	case "warn":
		return 0xD97706
	case "info":
		return 0x3B82F6
	default:
		return b.cfg.Notifications.EmbedColors.Action
	}
}

func (b *Bot) buildActionEmbed(lang, userID, action string, riskScore, trustScore, effective float64, auditOnly bool) *discordgo.MessageEmbed {
	severity := b.severityLabel(lang, action)
	if severity == "" {
		severity = b.t(lang, "severity_info")
	}
	color := b.actionColor(action)
	statusVal := b.t(lang, "status_applied")
	if auditOnly {
		statusVal = b.t(lang, "status_audit")
		color = 0x6B7280
	}

	return &discordgo.MessageEmbed{
		Title:       b.actionIcon(action) + "  " + b.t(lang, "action_title"),
		Description: "> <@" + userID + "> — **" + b.actionLabel(lang, action) + "**",
		Color:       color,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: "👤 " + b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
			{Name: "⚡ " + b.t(lang, "field_action"), Value: b.actionLabel(lang, action), Inline: true},
			{Name: "📊 " + b.t(lang, "field_severity"), Value: severity, Inline: true},
			{Name: "🔺 " + b.t(lang, "field_risk"), Value: fmt.Sprintf("%.1f", riskScore), Inline: true},
			{Name: "🛡️ " + b.t(lang, "field_trust"), Value: fmt.Sprintf("%.1f", trustScore), Inline: true},
			{Name: "⚖️ " + b.t(lang, "field_effective"), Value: fmt.Sprintf("%.1f", effective), Inline: true},
			{Name: "🔎 " + b.t(lang, "field_status"), Value: statusVal, Inline: false},
		},
	}
}

func (b *Bot) buildUserWarningEmbed(lang, action string, riskScore, trustScore, effective float64, auditOnly bool) *discordgo.MessageEmbed {
	color := b.actionColor(action)
	note := b.t(lang, "status_applied")
	if auditOnly {
		note = b.t(lang, "status_audit")
		color = 0x6B7280
	}
	severity := b.severityLabel(lang, action)
	if severity == "" {
		severity = b.t(lang, "severity_info")
	}

	return &discordgo.MessageEmbed{
		Title:       b.actionIcon(action) + "  " + b.t(lang, "warning_title"),
		Description: b.t(lang, "warning_desc"),
		Color:       color,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: "⚡ " + b.t(lang, "field_action"), Value: b.actionLabel(lang, action), Inline: true},
			{Name: "📊 " + b.t(lang, "field_severity"), Value: severity, Inline: true},
			{Name: "🔎 " + b.t(lang, "field_status"), Value: note, Inline: true},
		},
	}
}

func (b *Bot) buildAntiHateUserWarningEmbed(lang, action string, riskScore, trustScore, effective float64, auditOnly bool, strike int) *discordgo.MessageEmbed {
	embed := b.buildUserWarningEmbed(lang, action, riskScore, trustScore, effective, auditOnly)
	embed.Fields = append(embed.Fields, b.antiHateWarningExtraField(lang, strike))
	return embed
}

func (b *Bot) buildChannelWarningEmbed(lang, userID, action string, riskScore, trustScore, effective float64, auditOnly bool, count int, extraFields ...*discordgo.MessageEmbedField) *discordgo.MessageEmbed {
	color := b.actionColor(action)
	status := b.t(lang, "status_applied")
	if auditOnly {
		status = b.t(lang, "status_audit")
		color = 0x6B7280
	}
	severity := b.severityLabel(lang, action)
	if severity == "" {
		severity = b.t(lang, "severity_info")
	}

	title := b.actionIcon(action) + "  " + b.t(lang, "warning_title")
	if count > 1 {
		title += fmt.Sprintf(" (×%d)", count)
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: "👤 " + b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
		{Name: "⚡ " + b.t(lang, "field_action"), Value: b.actionLabel(lang, action), Inline: true},
		{Name: "📊 " + b.t(lang, "field_severity"), Value: severity, Inline: true},
		{Name: "🔺 " + b.t(lang, "field_risk"), Value: fmt.Sprintf("%.1f", riskScore), Inline: true},
		{Name: "🛡️ " + b.t(lang, "field_trust"), Value: fmt.Sprintf("%.1f", trustScore), Inline: true},
		{Name: "⚖️ " + b.t(lang, "field_effective"), Value: fmt.Sprintf("%.1f", effective), Inline: true},
		{Name: "🔎 " + b.t(lang, "field_status"), Value: status, Inline: false},
	}
	fields = append(fields, extraFields...)

	return &discordgo.MessageEmbed{
		Title:       title,
		Description: "> <@" + userID + "> — " + b.t(lang, "warning_desc_channel"),
		Color:       color,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields:      fields,
	}
}

func (b *Bot) antiHateWarningExtraField(lang string, strike int) *discordgo.MessageEmbedField {
	return &discordgo.MessageEmbedField{
		Name:   "📊 " + b.t(lang, "field_ban_progress"),
		Value:  antiHateProgressText(lang, strike),
		Inline: false,
	}
}

func (b *Bot) handlePhishingDetection(ctx context.Context, guildID, userID, detail string, auditOnly bool) int {
	threshold := b.phishingThreshold()
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
	messageID := agg.messageID
	channelID := agg.channelID
	b.detectAggMu.Unlock()

	if !b.cfg.Notifications.ChannelWarnEnabled {
		return count
	}
	settings := b.guildSettings(ctx, guildID)
	channelID = settings.SecurityLogChannel
	if channelID == "" {
		channelID = b.cfg.DefaultSecurityLogChannel
	}
	if channelID == "" {
		return count
	}
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	embed := b.buildDetectionWarningEmbed(lang, userID, detail, count, threshold, auditOnly)
	if messageID != "" && channelID == agg.channelID {
		if _, err := b.session.ChannelMessageEditEmbed(channelID, messageID, embed); err == nil {
			return count
		}
	}

	msg, err := b.session.ChannelMessageSendEmbed(channelID, embed)
	if err != nil || msg == nil {
		return count
	}
	b.detectAggMu.Lock()
	current := b.detectAgg[key]
	if current != nil {
		current.channelID = channelID
		current.messageID = msg.ID
	}
	b.detectAggMu.Unlock()
	return count
}

func (b *Bot) buildDetectionWarningEmbed(lang, userID, detail string, count, threshold int, auditOnly bool) *discordgo.MessageEmbed {
	color := 0x7C3AED // purple for phishing
	status := b.t(lang, "status_applied")
	if auditOnly {
		status = b.t(lang, "status_audit")
		color = 0x6B7280
	}

	progress := fmt.Sprintf("%d / %d", count, threshold)
	fields := []*discordgo.MessageEmbedField{
		{Name: "👤 " + b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
		{Name: "📈 " + b.t(lang, "field_count"), Value: progress, Inline: true},
		{Name: "🔎 " + b.t(lang, "field_status"), Value: status, Inline: true},
	}
	if detail != "" {
		fields = append(fields, &discordgo.MessageEmbedField{Name: "🔗 " + b.t(lang, "field_reason"), Value: "`" + detail + "`", Inline: false})
	}

	return &discordgo.MessageEmbed{
		Title:       "🎣  " + b.t(lang, "warning_phishing_title"),
		Description: "> <@" + userID + "> — " + b.t(lang, "warning_phishing_desc"),
		Color:       color,
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
	detail := reason
	if err != nil {
		detail = reason + "\n> `" + err.Error() + "`"
	}
	return &discordgo.MessageEmbed{
		Title:       "❌  " + b.t(lang, "error_title"),
		Description: detail,
		Color:       b.cfg.Notifications.EmbedColors.Error,
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: "👤 " + b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
		},
	}
}

// levelIcon returns an emoji for an audit log level.
func levelIcon(level string) string {
	switch level {
	case "crit":
		return "🚨"
	case "warn":
		return "⚠️"
	case "info":
		return "ℹ️"
	default:
		return "📋"
	}
}

func (b *Bot) buildAuditEmbed(lang string, entry storage.AuditLog, count int) *discordgo.MessageEmbed {
	userValue := "<@" + entry.UserID + ">"
	if entry.UserID == "" {
		userValue = b.t(lang, "value_system")
	}
	eventLabel := b.auditEventLabel(lang, entry.Event)
	formattedDetails := b.formatAuditDetails(lang, entry)

	title := levelIcon(entry.Level) + "  " + b.t(lang, "audit_title")
	if count > 1 {
		title += fmt.Sprintf(" (×%d)", count)
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: "📌 " + b.t(lang, "field_event"), Value: eventLabel, Inline: true},
		{Name: "👤 " + b.t(lang, "field_user"), Value: userValue, Inline: true},
		{Name: "🔖 " + b.t(lang, "audit_level"), Value: strings.ToUpper(entry.Level), Inline: true},
	}
	fields = append(fields, &discordgo.MessageEmbedField{Name: "📄 " + b.t(lang, "audit_details"), Value: formattedDetails, Inline: false})

	return &discordgo.MessageEmbed{
		Title:       title,
		Description: b.t(lang, "audit_desc"),
		Color:       b.levelColor(entry.Level),
		Author:      b.embedAuthor(lang),
		Footer:      b.embedFooter(lang),
		Timestamp:   entry.CreatedAt.Format(time.RFC3339),
		Fields:      fields,
	}
}

func (b *Bot) auditEventLabel(lang, event string) string {
	switch event {
	case "anti_phishing":
		return "🎣 " + b.t(lang, "event_anti_phishing")
	case "anti_spam":
		return "💬 " + b.t(lang, "event_anti_spam")
	case "anti_hate":
		return "🚩 " + b.t(lang, "event_anti_hate")
	case "anti_hate_enforcement":
		return "🔨 " + b.t(lang, "event_anti_hate_enforcement")
	case "anti_raid":
		return "🌊 " + b.t(lang, "event_anti_raid")
	case "risk_action":
		return "⚡ " + b.t(lang, "event_risk_action")
	case "enforcement_disabled":
		return "⏸️ " + b.t(lang, "event_enforcement_disabled")
	case "action_failed":
		return "❌ " + b.t(lang, "event_action_failed")
	case "action_skipped":
		return "⏭️ " + b.t(lang, "event_action_skipped")
	case "audit_mode":
		return "🔍 " + b.t(lang, "event_audit_mode")
	case "raid_lockdown":
		return "🔒 " + b.t(lang, "event_raid_lockdown")
	case "risk_reset":
		return "🔄 " + b.t(lang, "event_risk_reset")
	case "test":
		return "🧪 " + b.t(lang, "event_test")
	case "security":
		return "🛡️ " + b.t(lang, "event_security")
	case "anti_nuke":
		return "💣 " + b.t(lang, "event_anti_nuke")
	case "nuke_timeout":
		return "⏱️ " + b.t(lang, "event_nuke_timeout")
	default:
		return "📋 " + event
	}
}

func (b *Bot) formatAuditDetails(lang string, entry storage.AuditLog) string {
	if entry.Details == "" {
		return entry.Details
	}

	switch entry.Event {
	case "risk_action":
		details := entry.Details
		trigger := ""
		if idx := strings.Index(details, " trigger="); idx >= 0 {
			trigger = strings.TrimSpace(details[idx+len(" trigger="):])
			details = details[:idx]
		}
		parts := strings.Fields(details)
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
		if trigger != "" {
			lines = append(lines, b.t(lang, "label_cause")+": "+b.clipAuditDetails(trigger))
		}
		if len(lines) == 0 {
			return b.clipAuditDetails(entry.Details)
		}
		return strings.Join(lines, "\n")
	}

	return b.clipAuditDetails(entry.Details)
}

func (b *Bot) clipAuditDetails(details string) string {
	const maxLen = 980
	trimmed := strings.TrimSpace(details)
	if len(trimmed) <= maxLen {
		return trimmed
	}
	return trimmed[:maxLen] + "..."
}

func (b *Bot) notifyAudit(ctx context.Context, entry storage.AuditLog) {
	settings := b.guildSettings(ctx, entry.GuildID)
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

	key := entry.GuildID + "|" + entry.Level + "|" + entry.Event + "|" + entry.Details + "|" + entry.UserID
	window := 10 * time.Minute

	b.auditAggMu.Lock()
	agg := b.auditAgg[key]
	if agg != nil && agg.channelID == channelID && time.Since(agg.lastAt) <= window {
		agg.count++
		agg.lastAt = time.Now()
		count := agg.count
		messageID := agg.messageID
		b.auditAggMu.Unlock()
		embed := b.buildAuditEmbed(lang, entry, count)
		if _, err := b.session.ChannelMessageEditEmbed(channelID, messageID, embed); err == nil {
			return
		}
		b.auditAggMu.Lock()
		delete(b.auditAgg, key)
		b.auditAggMu.Unlock()
	}
	b.auditAggMu.Unlock()

	embed := b.buildAuditEmbed(lang, entry, 1)
	msg, err := b.session.ChannelMessageSendEmbed(channelID, embed)
	if err != nil || msg == nil {
		return
	}
	b.auditAggMu.Lock()
	b.auditAgg[key] = &auditAggregate{channelID: channelID, messageID: msg.ID, count: 1, lastAt: time.Now()}
	b.auditAggMu.Unlock()
}

func (b *Bot) startDailySummary() {
	if !b.cfg.Notifications.DailySummary {
		return
	}
	go func() {
		time.Sleep(30 * time.Second)
		b.sendDailySummary()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			b.sendDailySummary()
		}
	}()
}

// startCleanup periodically removes stale entries from in-memory maps to bound memory usage.
func (b *Bot) startCleanup() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.antispam.Cleanup()
			case <-b.rootCtx.Done():
				return
			}
		}
	}()
}

func (b *Bot) sendDailySummary() {
	if b.session == nil || b.session.State == nil {
		return
	}
	ctx := context.Background()
	for _, guild := range b.session.State.Guilds {
		if guild == nil {
			continue
		}
		settings := b.guildSettings(ctx, guild.ID)
		if settings.SecurityLogChannel == "" && b.cfg.DefaultSecurityLogChannel == "" {
			continue
		}
		lang := settings.Language
		if lang == "" {
			lang = b.cfg.DefaultLanguage
		}
		b.sendSecurityEmbed(ctx, guild.ID, b.buildDailySummaryEmbed(lang, guild.ID))
	}
}

func (b *Bot) buildDailySummaryEmbed(lang, guildID string) *discordgo.MessageEmbed {
	riskLines := b.buildRiskSummaryLines(lang, guildID, 5)
	voiceLines := b.buildVoiceSummaryLines(guildID, 5, 25)
	if voiceLines == "" {
		voiceLines = b.t(lang, "value_none")
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: "🔺 " + b.t(lang, "field_risk_top"), Value: riskLines, Inline: false},
		{Name: "🎙️ " + b.t(lang, "field_voice"), Value: voiceLines, Inline: false},
	}

	return &discordgo.MessageEmbed{
		Title:       "📊  " + b.t(lang, "daily_summary_title"),
		Description: b.t(lang, "daily_summary_desc"),
		Color:       0x3B82F6,
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
	case "warn", "delete":
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
	case "warn":
		return b.t(lang, "action_warn")
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
		Language:           b.cfg.DefaultLanguage,
		Mode:               b.cfg.Mode,
		RulePreset:         b.cfg.RulePreset,
		RetentionDays:      b.cfg.RetentionDays,
		SpamMessages:       b.cfg.Thresholds.SpamMessages,
		SpamWindowSeconds:  b.cfg.Thresholds.SpamWindowSeconds,
		RaidJoins:          b.cfg.Thresholds.RaidJoins,
		RaidWindowSeconds:  b.cfg.Thresholds.RaidWindowSeconds,
		PhishingRisk:       b.cfg.Thresholds.PhishingRisk,
		LockdownEnabled:    false,
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
		b.logger.Warn("guild settings fallback used", zap.Error(err))
		return defaults
	}
	return settings
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
	channelID := settings.SecurityLogChannel
	if channelID == "" {
		channelID = b.cfg.DefaultSecurityLogChannel
	}
	if channelID == "" {
		return
	}
	_, _ = b.session.ChannelMessageSend(channelID, message)
}

func formatReport(report analytics.Report) string {
	return fmt.Sprintf("Total: %d | INFO: %d | WARN: %d | CRIT: %d", report.Total, report.ByLevel[audit.LevelInfo], report.ByLevel[audit.LevelWarn], report.ByLevel[audit.LevelCrit])
}
