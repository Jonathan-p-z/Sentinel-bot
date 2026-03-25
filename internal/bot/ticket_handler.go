package bot

import (
	"context"
	"fmt"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/modules/tickets"

	"github.com/bwmarrin/discordgo"
)

func (b *Bot) handleTicketCommand(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate) {
	if interaction.GuildID == "" {
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t("fr", "ticket_title"), b.t("fr", "error_only_guild"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	settings := b.guildSettings(ctx, interaction.GuildID)
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	userID := interactionActorID(interaction)
	if userID == "" {
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_user_ctx"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	existing, err := b.store.GetOpenTicket(ctx, interaction.GuildID, userID)
	if err != nil {
		b.logger.Sugar().Errorw("get open ticket", "err", err)
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}
	if existing != nil {
		msg := fmt.Sprintf(b.t(lang, "ticket_already_open"), existing.ChannelID)
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), msg, b.cfg.Notifications.EmbedColors.Warning, nil),
			true)
		return
	}

	sub, err := b.store.GetSubscription(ctx, interaction.GuildID)
	plan := "free"
	if err == nil && sub != nil && sub.Plan != "" {
		plan = sub.Plan
	}

	count, err := b.store.CountOpenTickets(ctx, interaction.GuildID)
	if err != nil {
		b.logger.Sugar().Errorw("count open tickets", "err", err)
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	limit := tickets.TierLimit(plan)
	if count >= limit {
		msg := fmt.Sprintf(b.t(lang, "ticket_limit_reached"), limit)
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), msg, b.cfg.Notifications.EmbedColors.Warning, nil),
			true)
		return
	}

	categoryID := settings.TicketCategoryID
	if categoryID == "" {
		categoryID = tickets.FindTicketCategory(session, interaction.GuildID)
	}

	username := interactionActorName(interaction)
	if interaction.Member != nil && interaction.Member.User != nil {
		username = interaction.Member.User.Username
	}

	ch, err := tickets.CreateTicketChannel(session, interaction.GuildID, categoryID, userID, username)
	if err != nil {
		b.logger.Sugar().Errorw("create ticket channel", "err", err)
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	if err := b.store.CreateTicket(ctx, interaction.GuildID, userID, ch.ID); err != nil {
		b.logger.Sugar().Errorw("persist ticket", "err", err)
		// Best-effort cleanup: delete the Discord channel we just created.
		_, _ = session.ChannelDelete(ch.ID)
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	if err := tickets.SendWelcomeMessage(session, ch.ID, userID, lang); err != nil {
		b.logger.Sugar().Warnw("send ticket welcome", "err", err)
	}

	b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, userID, "ticket_open",
		fmt.Sprintf("channel=%s", ch.ID))

	msg := fmt.Sprintf(b.t(lang, "ticket_created"), ch.ID)
	b.respondEmbed(session, interaction,
		b.commandEmbed(b.t(lang, "ticket_title"), msg, b.cfg.Notifications.EmbedColors.Action, nil),
		true)
}

func (b *Bot) handleTicketClose(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate) {
	settings := b.guildSettings(ctx, interaction.GuildID)
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	channelID := interaction.ChannelID
	actorID := interactionActorID(interaction)

	ticket, err := b.store.GetTicketByChannel(ctx, channelID)
	if err != nil || ticket == nil {
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "ticket_not_found"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	isOwner := actorID == ticket.UserID
	isStaff := interaction.Member != nil &&
		interaction.Member.Permissions&discordgo.PermissionManageServer != 0

	if !isOwner && !isStaff {
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_no_permission"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	_ = session.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Flags: discordgo.MessageFlagsEphemeral,
		},
	})

	ch, _ := session.Channel(channelID)
	channelName := channelID
	if ch != nil {
		channelName = ch.Name
	}

	transcript := tickets.GenerateTranscript(session, channelID)

	logChannelID, err := tickets.EnsureLogChannel(session, interaction.GuildID)
	if err != nil {
		b.logger.Sugar().Warnw("ensure log channel", "err", err)
	} else {
		tickets.PostTranscript(session, logChannelID, channelName, transcript)
	}

	if err := b.store.CloseTicket(ctx, channelID); err != nil {
		b.logger.Sugar().Errorw("close ticket db", "err", err)
	}

	b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, actorID, "ticket_close",
		fmt.Sprintf("channel=%s owner=%s", channelID, ticket.UserID))

	_, _ = session.ChannelDelete(channelID)
}

func (b *Bot) handleTicketHelp(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate) {
	_ = ctx
	settings := b.guildSettings(ctx, interaction.GuildID)
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	_ = session.InteractionRespond(interaction.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{
				b.commandEmbed(
					b.t(lang, "ticket_help_title"),
					b.t(lang, "ticket_help_body"),
					b.cfg.Notifications.EmbedColors.Action,
					nil,
				),
			},
			Flags: discordgo.MessageFlagsEphemeral,
		},
	})
}

func (b *Bot) handleTicketSetup(ctx context.Context, session *discordgo.Session, interaction *discordgo.InteractionCreate) {
	if interaction.GuildID == "" {
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t("fr", "ticket_title"), b.t("fr", "error_only_guild"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	settings := b.guildSettings(ctx, interaction.GuildID)
	lang := settings.Language
	if lang == "" {
		lang = b.cfg.DefaultLanguage
	}

	if interaction.Member == nil || interaction.Member.Permissions&discordgo.PermissionManageServer == 0 {
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_no_permission"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	opts := interaction.ApplicationCommandData().Options
	if len(opts) == 0 || len(opts[0].Options) == 0 {
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}
	categoryID := opts[0].Options[0].StringValue()

	if err := b.store.SetTicketCategoryID(ctx, interaction.GuildID, categoryID); err != nil {
		b.logger.Sugar().Errorw("set ticket category", "err", err)
		b.respondEmbed(session, interaction,
			b.commandEmbed(b.t(lang, "ticket_title"), b.t(lang, "error_failed"), b.cfg.Notifications.EmbedColors.Error, nil),
			true)
		return
	}

	b.audit.Log(ctx, audit.LevelInfo, interaction.GuildID, interactionActorID(interaction), "ticket_setup",
		fmt.Sprintf("category=%s", categoryID))

	msg := fmt.Sprintf(b.t(lang, "ticket_setup_ok"), categoryID)
	b.respondEmbed(session, interaction,
		b.commandEmbed(b.t(lang, "ticket_title"), msg, b.cfg.Notifications.EmbedColors.Action, nil),
		true)
}
