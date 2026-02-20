package bot

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
	"go.uber.org/zap"
)

func (b *Bot) onInteractionCreate(session *discordgo.Session, interaction *discordgo.InteractionCreate) {
	if interaction.Type != discordgo.InteractionApplicationCommand {
		return
	}

	ctx := context.Background()
	data := interaction.ApplicationCommandData()
	switch data.Name {
	case "status", "mode", "preset", "lockdown", "rules", "domain", "report", "language", "test", "logs", "risk":
		b.handleSecurityCommand(ctx, session, interaction, data.Name, data.Options)
	case "verify":
		b.verify.HandleVerify(ctx)
		lang := b.cfg.DefaultLanguage
		if interaction.GuildID != "" {
			lang = b.guildSettings(ctx, interaction.GuildID).Language
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "verify_title"), b.t(lang, "verify_requested"), b.cfg.Notifications.EmbedColors.Action, nil), true)
	}
}

func (b *Bot) handleSecurityCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, name string, options []*discordgo.ApplicationCommandInteractionDataOption) {
	if interaction.GuildID == "" {
		lang := b.cfg.DefaultLanguage
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_title"), b.t(lang, "error_only_guild"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	settings := b.guildSettings(ctx, interaction.GuildID)
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	switch name {
	case "status":
		state := b.playbook.IsLockdown(interaction.GuildID)
		fields := []*discordgo.MessageEmbedField{
			{Name: b.t(lang, "field_mode"), Value: settings.Mode, Inline: true},
			{Name: b.t(lang, "field_preset"), Value: settings.RulePreset, Inline: true},
			{Name: b.t(lang, "field_lockdown"), Value: fmt.Sprintf("%t", state.Lockdown), Inline: true},
			{Name: b.t(lang, "field_strict"), Value: fmt.Sprintf("%t", state.Strict), Inline: true},
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_status_title"), b.t(lang, "security_status_desc"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "logs":
		if len(options) == 0 {
			value := settings.SecurityLogChannel
			if value == "" {
				value = b.t(lang, "value_not_set")
			}
			fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_channel"), Value: value, Inline: true}}
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "security_logs_current"), b.cfg.Notifications.EmbedColors.Action, fields), true)
			return
		}
		channel := options[0].ChannelValue(session)
		if channel == nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		settings.SecurityLogChannel = channel.ID
		if err := b.store.UpsertGuildSettings(ctx, settings); err != nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_channel"), Value: "<#" + channel.ID + ">", Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "security_logs_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "risk":
		if len(options) == 0 {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_risk_title"), b.t(lang, "error_no_subcommand"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		action := options[0].StringValue()
		if action != "reset" {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_risk_title"), b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		userID := ""
		if len(options) > 1 && options[1].Type == discordgo.ApplicationCommandOptionUser {
			userID = options[1].UserValue(session).ID
		}
		if userID == "" && interaction.Member != nil && interaction.Member.User != nil {
			userID = interaction.Member.User.ID
		}
		if userID == "" {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_risk_title"), b.t(lang, "error_user_ctx"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		b.risk.Reset(interaction.GuildID, userID)
		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, userID, "risk_reset", "risk score reset")
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_risk_title"), b.t(lang, "security_risk_reset"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "mode":
		if len(options) == 0 {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_mode_title"), b.t(lang, "error_no_subcommand"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		value := options[0].StringValue()
		settings.Mode = value
		if err := b.store.UpsertGuildSettings(ctx, settings); err != nil {
			b.logger.Warn("mode update failed", zap.Error(err))
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_mode_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_mode"), Value: value, Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_mode_title"), b.t(lang, "security_mode_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "preset":
		if len(options) == 0 {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_preset_title"), b.t(lang, "error_no_subcommand"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		value := options[0].StringValue()
		settings.RulePreset = value
		if err := b.store.UpsertGuildSettings(ctx, settings); err != nil {
			b.logger.Warn("preset update failed", zap.Error(err))
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_preset_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_preset"), Value: value, Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_preset_title"), b.t(lang, "security_preset_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "lockdown":
		if len(options) == 0 {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_lockdown_title"), b.t(lang, "error_no_subcommand"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		value := options[0].StringValue()
		if value == "on" {
			b.playbook.TriggerLockdown(ctx, interaction.GuildID)
			settings.LockdownEnabled = true
		} else {
			settings.LockdownEnabled = false
		}
		_ = b.store.UpsertGuildSettings(ctx, settings)
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_lockdown"), Value: value, Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_lockdown_title"), b.t(lang, "security_lockdown_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "rules":
		b.handleRulesCommand(ctx, session, interaction, settings, options)
	case "domain":
		b.handleDomainCommand(ctx, session, interaction, options)
	case "report":
		if len(options) == 0 {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_report_title"), b.t(lang, "error_no_subcommand"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		period := options[0].StringValue()
		start := time.Now().Add(-24 * time.Hour)
		if period == "week" {
			start = time.Now().Add(-7 * 24 * time.Hour)
		}
		report, err := b.analytics.Report(ctx, interaction.GuildID, start)
		if err != nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_report_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		fields := []*discordgo.MessageEmbedField{
			{Name: b.t(lang, "field_total"), Value: fmt.Sprintf("%d", report.Total), Inline: true},
			{Name: b.t(lang, "field_info"), Value: fmt.Sprintf("%d", report.ByLevel[audit.LevelInfo]), Inline: true},
			{Name: b.t(lang, "field_warn"), Value: fmt.Sprintf("%d", report.ByLevel[audit.LevelWarn]), Inline: true},
			{Name: b.t(lang, "field_crit"), Value: fmt.Sprintf("%d", report.ByLevel[audit.LevelCrit]), Inline: true},
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_report_title"), b.t(lang, "security_report_desc"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "language":
		if len(options) == 0 {
			fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_language"), Value: settings.Language, Inline: true}}
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_language_title"), b.t(lang, "security_language_current"), b.cfg.Notifications.EmbedColors.Action, fields), true)
			return
		}
		value := options[0].StringValue()
		if value != "fr" && value != "en" && value != "es" {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_language_title"), b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		settings.Language = value
		if err := b.store.UpsertGuildSettings(ctx, settings); err != nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_language_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(value, "field_language"), Value: value, Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(value, "security_language_title"), b.t(value, "security_language_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "test":
		b.handleTestCommand(ctx, session, interaction, settings, options)
	default:
		b.respondEmbed(session, interaction, b.commandEmbed("Security", b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
	}
}

func (b *Bot) handleTestCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, settings storage.GuildSettings, options []*discordgo.ApplicationCommandInteractionDataOption) {
	if interaction.Member == nil || interaction.Member.User == nil {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "error_user_ctx"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}
	if len(options) == 0 {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "error_scenario"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	scenario := options[0].StringValue()
	userID := interaction.Member.User.ID
	auditOnly := b.isAuditMode(settings)

	switch scenario {
	case "raid":
		triggered := b.playbook.TriggerLockdown(ctx, interaction.GuildID)
		if triggered {
			b.audit.Log(ctx, audit.LevelWarn, interaction.GuildID, userID, "test", "raid lockdown simulated")
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_raid"), b.cfg.Notifications.EmbedColors.Action, nil), true)
			return
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_raid_active"), b.cfg.Notifications.EmbedColors.Warning, nil), true)
		return
	case "spam":
		score := b.risk.AddRisk(interaction.GuildID, userID, 12)
		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, userID, "test", "spam signal simulated")
		b.applyRiskActions(ctx, interaction.GuildID, userID, score, auditOnly)
		fields := []*discordgo.MessageEmbedField{{Name: b.t(settings.Language, "field_risk_score"), Value: fmt.Sprintf("%.1f", score), Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_spam"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	case "phishing":
		score := b.risk.AddRisk(interaction.GuildID, userID, float64(settings.PhishingRisk))
		b.audit.Log(ctx, audit.LevelWarn, interaction.GuildID, userID, "test", "phishing signal simulated")
		b.applyRiskActions(ctx, interaction.GuildID, userID, score, auditOnly)
		fields := []*discordgo.MessageEmbedField{{Name: b.t(settings.Language, "field_risk_score"), Value: fmt.Sprintf("%.1f", score), Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_phishing"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	case "risk":
		points := int64(10)
		if len(options) > 1 && options[1].Type == discordgo.ApplicationCommandOptionInteger {
			points = options[1].IntValue()
		}
		score := b.risk.AddRisk(interaction.GuildID, userID, float64(points))
		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, userID, "test", "risk points added")
		b.applyRiskActions(ctx, interaction.GuildID, userID, score, auditOnly)
		fields := []*discordgo.MessageEmbedField{{Name: b.t(settings.Language, "field_risk_score"), Value: fmt.Sprintf("%.1f", score), Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_risk"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	default:
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}
}

func (b *Bot) handleRulesCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, settings storage.GuildSettings, options []*discordgo.ApplicationCommandInteractionDataOption) {
	if len(options) == 0 {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_rules_title"), b.t(settings.Language, "error_rules_action"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	action := options[0].StringValue()
	if action == "view" {
		fields := []*discordgo.MessageEmbedField{
			{Name: b.t(settings.Language, "field_spam"), Value: fmt.Sprintf("%d/%ds", settings.SpamMessages, settings.SpamWindowSeconds), Inline: true},
			{Name: b.t(settings.Language, "field_raid"), Value: fmt.Sprintf("%d/%ds", settings.RaidJoins, settings.RaidWindowSeconds), Inline: true},
			{Name: b.t(settings.Language, "field_phishing"), Value: fmt.Sprintf("%d", settings.PhishingRisk), Inline: true},
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_rules_title"), b.t(settings.Language, "security_rules_current"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	}

	if action != "set" {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_rules_title"), b.t(settings.Language, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	for _, opt := range options[1:] {
		switch opt.Name {
		case "spam_messages":
			settings.SpamMessages = int(opt.IntValue())
		case "spam_window":
			settings.SpamWindowSeconds = int(opt.IntValue())
		case "raid_joins":
			settings.RaidJoins = int(opt.IntValue())
		case "raid_window":
			settings.RaidWindowSeconds = int(opt.IntValue())
		case "phishing_risk":
			settings.PhishingRisk = int(opt.IntValue())
		}
	}

	if err := b.store.UpsertGuildSettings(ctx, settings); err != nil {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_rules_title"), b.t(settings.Language, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}
	fields := []*discordgo.MessageEmbedField{
		{Name: b.t(settings.Language, "field_spam"), Value: fmt.Sprintf("%d/%ds", settings.SpamMessages, settings.SpamWindowSeconds), Inline: true},
		{Name: b.t(settings.Language, "field_raid"), Value: fmt.Sprintf("%d/%ds", settings.RaidJoins, settings.RaidWindowSeconds), Inline: true},
		{Name: b.t(settings.Language, "field_phishing"), Value: fmt.Sprintf("%d", settings.PhishingRisk), Inline: true},
	}
	b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_rules_title"), b.t(settings.Language, "security_rules_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
}

func (b *Bot) handleDomainCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, options []*discordgo.ApplicationCommandInteractionDataOption) {
	settings := b.guildSettings(ctx, interaction.GuildID)
	lang := settings.Language
	if len(options) < 2 {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "error_domain_required"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	listType := options[0].StringValue()
	action := options[1].StringValue()
	domain := ""
	if len(options) > 2 {
		domain = strings.ToLower(options[2].StringValue())
	}

	switch listType {
	case "allow":
		b.handleDomainList(ctx, session, interaction, action, domain, true, lang)
	case "block":
		b.handleDomainList(ctx, session, interaction, action, domain, false, lang)
	default:
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
	}
}

func (b *Bot) handleDomainList(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, action, domain string, allow bool, lang string) {
	guildID := interaction.GuildID

	switch action {
	case "add":
		if domain == "" {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "error_domain_required"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		if allow {
			_ = b.store.AddDomainAllow(ctx, guildID, domain)
		} else {
			_ = b.store.AddDomainBlock(ctx, guildID, domain)
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_domain"), Value: domain, Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "security_domain_added"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "remove":
		if domain == "" {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "error_domain_required"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		if allow {
			_ = b.store.RemoveDomainAllow(ctx, guildID, domain)
		} else {
			_ = b.store.RemoveDomainBlock(ctx, guildID, domain)
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_domain"), Value: domain, Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "security_domain_removed"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "list":
		var domains []string
		var err error
		if allow {
			domains, err = b.store.ListDomainAllow(ctx, guildID)
		} else {
			domains, err = b.store.ListDomainBlock(ctx, guildID)
		}
		if err != nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "error_domain_list"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		if len(domains) == 0 {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "error_domain_empty"), b.cfg.Notifications.EmbedColors.Warning, nil), true)
			return
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_domains"), Value: strings.Join(domains, "\n"), Inline: false}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "security_domain_list"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	default:
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_domain_title"), b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
	}
}

func (b *Bot) commandEmbed(title, description string, color int, fields []*discordgo.MessageEmbedField) *discordgo.MessageEmbed {
	return &discordgo.MessageEmbed{
		Title:       title,
		Description: description,
		Color:       color,
		Timestamp:   time.Now().Format(time.RFC3339),
		Fields:      fields,
	}
}

func (b *Bot) auditSecurity(ctx context.Context, guildID, message string) {
	b.audit.Log(ctx, audit.LevelInfo, guildID, "", "security", message)
	b.auditToChannel(ctx, guildID, message)
}
