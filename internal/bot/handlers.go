package bot

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

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
	case "status", "mode", "preset", "lockdown", "rules", "domain", "report", "language", "test", "logs", "risk", "whitelist", "nuke", "feedback":
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
		channel, err := b.resolveLogChannelOption(session, interaction.GuildID, options[0])
		if err != nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "error_logs_channel_unreachable"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		if channel == nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "error_logs_channel_invalid"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		if !isLogChannelType(channel.Type) {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "error_logs_type"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		if err := b.ensureBotCanWriteChannel(session, channel.ID); err != nil {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_logs_title"), b.t(lang, "error_logs_permissions"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		settings.SecurityLogChannel = channel.ID
		if err := b.store.UpsertGuildSettings(ctx, settings); err != nil {
			b.logger.Warn("logs channel update failed", zap.String("guild_id", interaction.GuildID), zap.String("channel_id", channel.ID), zap.Error(err))
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
		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, userID, "risk_reset", fmt.Sprintf("user=<@%s> score_reset=true", userID))
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
			b.enterLockdown(ctx, interaction.GuildID, "manual")
		} else {
			b.restoreLockdown(ctx, interaction.GuildID, "manual")
		}
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
	case "whitelist":
		b.handleWhitelistCommand(ctx, session, interaction, settings, options)
	case "nuke":
		b.handleNukeCommand(ctx, session, interaction, settings, options)
	case "feedback":
		b.handleFeedbackCommand(ctx, session, interaction, settings, options)
	default:
		b.respondEmbed(session, interaction, b.commandEmbed("Security", b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
	}
}

func (b *Bot) handleFeedbackCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, settings storage.GuildSettings, options []*discordgo.ApplicationCommandInteractionDataOption) {
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}
	if interaction.Member == nil || interaction.Member.User == nil {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "error_user_ctx"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	quickOpen := len(options) == 0
	action := "open"
	actionOptions := []*discordgo.ApplicationCommandInteractionDataOption{}
	if !quickOpen {
		action = options[0].Name
		actionOptions = options[0].Options
		if action != "open" && action != "close" {
			action = options[0].StringValue()
			actionOptions = options
		}
	}

	if (action == "close" || (action == "open" && !quickOpen)) && !b.userIsAboveBot(interaction.GuildID, interaction.Member.User.ID) {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "error_feedback_staff_only"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	if action == "close" {
		channel, err := session.Channel(interaction.ChannelID)
		if err != nil || channel == nil || channel.GuildID != interaction.GuildID || !strings.HasPrefix(channel.Topic, "feedback_ticket:") {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "error_feedback_close_context"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}

		reason := "resolved"
		if len(actionOptions) > 0 {
			parsed := strings.TrimSpace(actionOptions[0].StringValue())
			if parsed != "" {
				reason = parsed
			}
		}

		ticketOwnerID := strings.TrimPrefix(channel.Topic, "feedback_ticket:")
		requesterID := interaction.Member.User.ID

		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, requesterID, "feedback_ticket_close", fmt.Sprintf("user=<@%s> channel=%s owner=<@%s> reason=%q", requesterID, channel.ID, ticketOwnerID, reason))
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "security_feedback_ticket_closed"), b.cfg.Notifications.EmbedColors.Action, []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_reason"), Value: reason, Inline: false}}), true)
		_, _ = session.ChannelMessageSend(channel.ID, "🔒 "+b.t(lang, "security_feedback_ticket_closed"))
		_, _ = session.ChannelDelete(channel.ID)
		return
	}

	if action != "open" {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	feedbackType, message, domain, targetUserID := parseFeedbackOpenOptions(session, actionOptions)
	if quickOpen {
		feedbackType = "other"
		message = b.t(lang, "security_feedback_prompt")
	}
	if message == "" {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "error_feedback_message"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	if feedbackType == "" {
		feedbackType = "other"
	}

	guild, err := session.Guild(interaction.GuildID)
	if err != nil || guild == nil {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	requesterID := interaction.Member.User.ID
	userID := requesterID
	if targetUserID != "" {
		userID = targetUserID
	}
	details := fmt.Sprintf("user=<@%s> target=<@%s> type=%s message=%q", requesterID, userID, feedbackType, message)
	if domain != "" {
		details += " domain=" + domain
	}
	b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, requesterID, "feedback", details)

	targetUsername := interaction.Member.User.Username
	if userID != requesterID {
		if member, err := session.GuildMember(interaction.GuildID, userID); err == nil && member != nil && member.User != nil {
			targetUsername = member.User.Username
		}
	}

	overwrites := []*discordgo.PermissionOverwrite{
		{ID: guild.ID, Type: discordgo.PermissionOverwriteTypeRole, Deny: discordgo.PermissionViewChannel},
		{ID: userID, Type: discordgo.PermissionOverwriteTypeMember, Allow: discordgo.PermissionViewChannel | discordgo.PermissionSendMessages | discordgo.PermissionReadMessageHistory | discordgo.PermissionAttachFiles},
	}
	overwrites = append(overwrites, b.feedbackStaffOverwrites(guild)...)

	channelName := feedbackTicketChannelName(targetUsername, userID)
	created, err := session.GuildChannelCreateComplex(interaction.GuildID, discordgo.GuildChannelCreateData{
		Name:                 channelName,
		Type:                 discordgo.ChannelTypeGuildText,
		Topic:                "feedback_ticket:" + userID,
		PermissionOverwrites: overwrites,
	})
	if err != nil || created == nil {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "error_feedback_channel_create"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	autoAllowlisted := false
	if feedbackType == "false_positive" && domain != "" && b.memberCanManageFeedbackDomains(session, interaction) {
		_ = b.store.AddDomainAllow(ctx, interaction.GuildID, domain)
		_ = b.store.RemoveDomainBlock(ctx, interaction.GuildID, domain)
		autoAllowlisted = true
		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, requesterID, "feedback_allowlist", fmt.Sprintf("user=<@%s> target=<@%s> domain=%s auto_allowlisted=true", requesterID, userID, domain))
	}

	fields := []*discordgo.MessageEmbedField{
		{Name: b.t(lang, "field_feedback_type"), Value: feedbackType, Inline: true},
		{Name: b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true},
	}
	if domain != "" {
		fields = append(fields, &discordgo.MessageEmbedField{Name: b.t(lang, "field_domain"), Value: domain, Inline: true})
	}
	if autoAllowlisted {
		fields = append(fields, &discordgo.MessageEmbedField{Name: b.t(lang, "field_status"), Value: b.t(lang, "feedback_allowlisted"), Inline: false})
	}

	b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_feedback_title"), b.t(lang, "security_feedback_ticket_opened"), b.cfg.Notifications.EmbedColors.Action, []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_channel"), Value: "<#" + created.ID + ">", Inline: true}}), true)
	_, _ = session.ChannelMessageSendEmbed(created.ID, &discordgo.MessageEmbed{
		Title:       b.t(lang, "security_feedback_title"),
		Description: message,
		Color:       b.cfg.Notifications.EmbedColors.Action,
		Fields:      fields,
	})
}

func parseFeedbackOpenOptions(session *discordgo.Session, options []*discordgo.ApplicationCommandInteractionDataOption) (string, string, string, string) {
	feedbackType := ""
	message := ""
	domain := ""
	targetUserID := ""
	for _, opt := range options {
		switch opt.Name {
		case "type":
			feedbackType = opt.StringValue()
		case "message":
			message = strings.TrimSpace(opt.StringValue())
		case "domain":
			domain = strings.ToLower(strings.TrimSpace(opt.StringValue()))
		case "user":
			if session != nil {
				if user := opt.UserValue(session); user != nil {
					targetUserID = user.ID
				}
			}
		}
	}
	return feedbackType, message, domain, targetUserID
}

func (b *Bot) feedbackStaffOverwrites(guild *discordgo.Guild) []*discordgo.PermissionOverwrite {
	if guild == nil || b.session == nil || b.session.State == nil || b.session.State.User == nil {
		return nil
	}

	botMember := b.memberForUser(guild.ID, b.session.State.User.ID)
	if botMember == nil {
		return nil
	}

	botHighest := highestRolePosition(guild, botMember)
	if botHighest < 0 {
		return nil
	}

	overwrites := make([]*discordgo.PermissionOverwrite, 0)
	allow := int64(discordgo.PermissionViewChannel | discordgo.PermissionSendMessages | discordgo.PermissionReadMessageHistory | discordgo.PermissionAttachFiles)
	for _, role := range guild.Roles {
		if role == nil || role.ID == guild.ID {
			continue
		}
		if role.Position > botHighest {
			overwrites = append(overwrites, &discordgo.PermissionOverwrite{
				ID:    role.ID,
				Type:  discordgo.PermissionOverwriteTypeRole,
				Allow: allow,
			})
		}
	}

	return overwrites
}

func feedbackTicketChannelName(username, userID string) string {
	base := strings.ToLower(strings.TrimSpace(username))
	if base == "" {
		base = "user"
	}
	builder := strings.Builder{}
	for _, r := range base {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			continue
		}
		if r == '-' || r == '_' || unicode.IsSpace(r) {
			builder.WriteRune('-')
		}
	}
	slug := strings.Trim(builder.String(), "-")
	if slug == "" {
		slug = "user"
	}
	if len(slug) > 20 {
		slug = slug[:20]
	}
	suffix := userID
	if len(suffix) > 4 {
		suffix = suffix[len(suffix)-4:]
	}
	return "feedback-" + slug + "-" + suffix
}

func (b *Bot) memberCanManageFeedbackDomains(session *discordgo.Session, interaction *discordgo.InteractionCreate) bool {
	if interaction == nil || interaction.GuildID == "" || interaction.Member == nil || interaction.Member.User == nil {
		return false
	}

	if session == nil {
		return false
	}

	guild, err := session.State.Guild(interaction.GuildID)
	if err != nil || guild == nil {
		guild, _ = session.Guild(interaction.GuildID)
	}
	if guild == nil {
		return false
	}
	if guild.OwnerID == interaction.Member.User.ID {
		return true
	}

	member := interaction.Member
	if member.GuildID == "" {
		member.GuildID = interaction.GuildID
	}
	return b.memberHasAdmin(guild, member)
}

func (b *Bot) handleWhitelistCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, settings storage.GuildSettings, options []*discordgo.ApplicationCommandInteractionDataOption) {
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}
	if len(options) == 0 {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_whitelist_title"), b.t(lang, "error_no_subcommand"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}
	action := options[0].StringValue()
	if action != "add" && action != "remove" && action != "list" {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_whitelist_title"), b.t(lang, "error_unknown"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}
	var userID string
	var roleID string
	for _, opt := range options[1:] {
		switch opt.Name {
		case "user":
			if opt.Type == discordgo.ApplicationCommandOptionUser && opt.UserValue(session) != nil {
				userID = opt.UserValue(session).ID
			}
		case "role":
			if opt.Type == discordgo.ApplicationCommandOptionRole && opt.RoleValue(session, interaction.GuildID) != nil {
				roleID = opt.RoleValue(session, interaction.GuildID).ID
			}
		}
	}

	if action == "list" {
		users, _ := b.store.ListWhitelistUsers(ctx, interaction.GuildID)
		roles, _ := b.store.ListWhitelistRoles(ctx, interaction.GuildID)
		userLines := b.t(lang, "value_none")
		roleLines := b.t(lang, "value_none")
		if len(users) > 0 {
			lines := make([]string, 0, len(users))
			for _, id := range users {
				lines = append(lines, "<@"+id+">")
			}
			userLines = strings.Join(lines, "\n")
		}
		if len(roles) > 0 {
			lines := make([]string, 0, len(roles))
			for _, id := range roles {
				lines = append(lines, "<@&"+id+">")
			}
			roleLines = strings.Join(lines, "\n")
		}
		fields := []*discordgo.MessageEmbedField{
			{Name: b.t(lang, "field_users"), Value: userLines, Inline: false},
			{Name: b.t(lang, "field_roles"), Value: roleLines, Inline: false},
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_whitelist_title"), b.t(lang, "security_whitelist_list"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	}

	if userID == "" && roleID == "" {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_whitelist_title"), b.t(lang, "error_whitelist_target"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}

	if userID != "" {
		if action == "add" {
			_ = b.store.AddWhitelistUser(ctx, interaction.GuildID, userID)
		} else if action == "remove" {
			_ = b.store.RemoveWhitelistUser(ctx, interaction.GuildID, userID)
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_user"), Value: "<@" + userID + ">", Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_whitelist_title"), b.t(lang, "security_whitelist_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	}

	if roleID != "" {
		if action == "add" {
			_ = b.store.AddWhitelistRole(ctx, interaction.GuildID, roleID)
		} else if action == "remove" {
			_ = b.store.RemoveWhitelistRole(ctx, interaction.GuildID, roleID)
		}
		fields := []*discordgo.MessageEmbedField{{Name: b.t(lang, "field_role"), Value: "<@&" + roleID + ">", Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_whitelist_title"), b.t(lang, "security_whitelist_updated"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	}
}

func (b *Bot) handleNukeCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate, settings storage.GuildSettings, options []*discordgo.ApplicationCommandInteractionDataOption) {
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}
	if len(options) == 0 {
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "error_no_subcommand"), b.cfg.Notifications.EmbedColors.Error, nil), true)
		return
	}
	action := options[0].StringValue()
	key := ""
	value := 0
	for _, opt := range options[1:] {
		if opt.Name == "key" {
			key = opt.StringValue()
		}
		if opt.Name == "value" {
			value = int(opt.IntValue())
		}
	}

	switch action {
	case "status":
		fields := []*discordgo.MessageEmbedField{
			{Name: b.t(lang, "field_enabled"), Value: fmt.Sprintf("%t", settings.NukeEnabled), Inline: true},
			{Name: b.t(lang, "field_window"), Value: fmt.Sprintf("%ds", settings.NukeWindowSeconds), Inline: true},
			{Name: b.t(lang, "field_channel_delete"), Value: fmt.Sprintf("%d", settings.NukeChannelDelete), Inline: true},
			{Name: b.t(lang, "field_channel_create"), Value: fmt.Sprintf("%d", settings.NukeChannelCreate), Inline: true},
			{Name: b.t(lang, "field_channel_update"), Value: fmt.Sprintf("%d", settings.NukeChannelUpdate), Inline: true},
			{Name: b.t(lang, "field_role_delete"), Value: fmt.Sprintf("%d", settings.NukeRoleDelete), Inline: true},
			{Name: b.t(lang, "field_role_create"), Value: fmt.Sprintf("%d", settings.NukeRoleCreate), Inline: true},
			{Name: b.t(lang, "field_role_update"), Value: fmt.Sprintf("%d", settings.NukeRoleUpdate), Inline: true},
			{Name: b.t(lang, "field_webhook_update"), Value: fmt.Sprintf("%d", settings.NukeWebhookUpdate), Inline: true},
			{Name: b.t(lang, "field_ban_add"), Value: fmt.Sprintf("%d", settings.NukeBanAdd), Inline: true},
			{Name: b.t(lang, "field_guild_update"), Value: fmt.Sprintf("%d", settings.NukeGuildUpdate), Inline: true},
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "security_nuke_status"), b.cfg.Notifications.EmbedColors.Action, fields), true)
	case "enable":
		settings.NukeEnabled = true
		_ = b.store.UpsertGuildSettings(ctx, settings)
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "security_nuke_updated"), b.cfg.Notifications.EmbedColors.Action, nil), true)
	case "disable":
		settings.NukeEnabled = false
		_ = b.store.UpsertGuildSettings(ctx, settings)
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "security_nuke_updated"), b.cfg.Notifications.EmbedColors.Action, nil), true)
	case "set":
		if key == "" {
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "error_nuke_action"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		switch key {
		case "window_seconds":
			settings.NukeWindowSeconds = value
		case "channel_delete":
			settings.NukeChannelDelete = value
		case "channel_create":
			settings.NukeChannelCreate = value
		case "channel_update":
			settings.NukeChannelUpdate = value
		case "role_delete":
			settings.NukeRoleDelete = value
		case "role_create":
			settings.NukeRoleCreate = value
		case "role_update":
			settings.NukeRoleUpdate = value
		case "webhook_update":
			settings.NukeWebhookUpdate = value
		case "ban_add":
			settings.NukeBanAdd = value
		case "guild_update":
			settings.NukeGuildUpdate = value
		default:
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "error_nuke_action"), b.cfg.Notifications.EmbedColors.Error, nil), true)
			return
		}
		_ = b.store.UpsertGuildSettings(ctx, settings)
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "security_nuke_updated"), b.cfg.Notifications.EmbedColors.Action, nil), true)
	default:
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(lang, "security_nuke_title"), b.t(lang, "error_nuke_action"), b.cfg.Notifications.EmbedColors.Error, nil), true)
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
		triggered := b.enterLockdown(ctx, interaction.GuildID, "test")
		if triggered {
			b.audit.Log(ctx, audit.LevelWarn, interaction.GuildID, userID, "test", fmt.Sprintf("user=<@%s> scenario=raid lockdown_simulated=true", userID))
			b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_raid"), b.cfg.Notifications.EmbedColors.Action, nil), true)
			return
		}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_raid_active"), b.cfg.Notifications.EmbedColors.Warning, nil), true)
		return
	case "spam":
		score := b.risk.AddRisk(interaction.GuildID, userID, 12)
		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, userID, "test", fmt.Sprintf("user=<@%s> scenario=spam simulated=true score=%.1f", userID, score))
		b.applyRiskActions(ctx, interaction.GuildID, userID, score, auditOnly, "test scenario=spam")
		fields := []*discordgo.MessageEmbedField{{Name: b.t(settings.Language, "field_risk_score"), Value: fmt.Sprintf("%.1f", score), Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_spam"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	case "phishing":
		score := b.risk.AddRisk(interaction.GuildID, userID, float64(settings.PhishingRisk))
		b.audit.Log(ctx, audit.LevelWarn, interaction.GuildID, userID, "test", fmt.Sprintf("user=<@%s> scenario=phishing simulated=true score=%.1f", userID, score))
		b.applyRiskActions(ctx, interaction.GuildID, userID, score, auditOnly, "test scenario=phishing")
		fields := []*discordgo.MessageEmbedField{{Name: b.t(settings.Language, "field_risk_score"), Value: fmt.Sprintf("%.1f", score), Inline: true}}
		b.respondEmbed(session, interaction, b.commandEmbed(b.t(settings.Language, "security_test_title"), b.t(settings.Language, "security_test_phishing"), b.cfg.Notifications.EmbedColors.Action, fields), true)
		return
	case "risk":
		points := int64(10)
		if len(options) > 1 && options[1].Type == discordgo.ApplicationCommandOptionInteger {
			points = options[1].IntValue()
		}
		score := b.risk.AddRisk(interaction.GuildID, userID, float64(points))
		b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, userID, "test", fmt.Sprintf("user=<@%s> scenario=risk simulated=true points=%d score=%.1f", userID, points, score))
		b.applyRiskActions(ctx, interaction.GuildID, userID, score, auditOnly, "test scenario=risk")
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

func (b *Bot) resolveLogChannelOption(session *discordgo.Session, guildID string, option *discordgo.ApplicationCommandInteractionDataOption) (*discordgo.Channel, error) {
	if option == nil {
		return nil, fmt.Errorf("missing option")
	}
	if channel := option.ChannelValue(session); channel != nil {
		return channel, nil
	}

	channelID, ok := option.Value.(string)
	if !ok || channelID == "" {
		return nil, fmt.Errorf("missing channel id")
	}

	if session != nil && session.State != nil {
		if channel, err := session.State.Channel(channelID); err == nil && channel != nil {
			return channel, nil
		}
	}

	if session == nil {
		return nil, fmt.Errorf("missing session")
	}
	channel, err := session.Channel(channelID)
	if err != nil {
		return nil, err
	}
	if channel == nil {
		return nil, fmt.Errorf("channel not found")
	}
	if guildID != "" && channel.GuildID != "" && channel.GuildID != guildID {
		return nil, fmt.Errorf("channel is not in guild")
	}
	return channel, nil
}

func (b *Bot) ensureBotCanWriteChannel(session *discordgo.Session, channelID string) error {
	if session == nil || session.State == nil || session.State.User == nil {
		return fmt.Errorf("bot user unavailable")
	}
	permissions, err := session.UserChannelPermissions(session.State.User.ID, channelID)
	if err != nil {
		return err
	}
	required := int64(discordgo.PermissionViewChannel | discordgo.PermissionSendMessages)
	if permissions&required != required {
		return fmt.Errorf("missing permissions")
	}
	return nil
}

func isLogChannelType(channelType discordgo.ChannelType) bool {
	switch channelType {
	case discordgo.ChannelTypeGuildText,
		discordgo.ChannelTypeGuildNews,
		discordgo.ChannelTypeGuildPublicThread,
		discordgo.ChannelTypeGuildPrivateThread,
		discordgo.ChannelTypeGuildNewsThread:
		return true
	default:
		return false
	}
}

func (b *Bot) auditSecurity(ctx context.Context, guildID, message string) {
	b.audit.Log(ctx, audit.LevelInfo, guildID, "", "security", message)
	b.auditToChannel(ctx, guildID, message)
}
