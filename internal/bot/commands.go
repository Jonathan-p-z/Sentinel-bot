package bot

import "github.com/bwmarrin/discordgo"

func (b *Bot) registerCommands() error {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "status",
			Description: "Show current security status",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Afficher le statut de securite",
				discordgo.EnglishUS: "Show current security status",
				discordgo.SpanishES: "Mostrar estado de seguridad",
			},
		},
		{
			Name:        "mode",
			Description: "Set mode (audit or normal)",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Definir le mode (audit ou normal)",
				discordgo.EnglishUS: "Set mode (audit or normal)",
				discordgo.SpanishES: "Definir modo (audit o normal)",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "value",
					Description: "audit or normal",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "audit ou normal",
						discordgo.EnglishUS: "audit or normal",
						discordgo.SpanishES: "audit o normal",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "audit", Value: "audit"},
						{Name: "normal", Value: "normal"},
					},
				},
			},
		},
		{
			Name:        "preset",
			Description: "Set rule preset",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Definir le profil de regles",
				discordgo.EnglishUS: "Set rule preset",
				discordgo.SpanishES: "Definir perfil de reglas",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "value",
					Description: "low, medium, or high",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "low, medium ou high",
						discordgo.EnglishUS: "low, medium, or high",
						discordgo.SpanishES: "low, medium o high",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "low", Value: "low"},
						{Name: "medium", Value: "medium"},
						{Name: "high", Value: "high"},
					},
				},
			},
		},
		{
			Name:        "lockdown",
			Description: "Toggle lockdown",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Activer ou desactiver le confinement",
				discordgo.EnglishUS: "Toggle lockdown",
				discordgo.SpanishES: "Activar o desactivar confinamiento",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "value",
					Description: "on or off",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "on ou off",
						discordgo.EnglishUS: "on or off",
						discordgo.SpanishES: "on u off",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "on", Value: "on"},
						{Name: "off", Value: "off"},
					},
				},
			},
		},
		{
			Name:        "rules",
			Description: "View or set rules",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Voir ou modifier les regles",
				discordgo.EnglishUS: "View or set rules",
				discordgo.SpanishES: "Ver o modificar reglas",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "action",
					Description: "view or set",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "view ou set",
						discordgo.EnglishUS: "view or set",
						discordgo.SpanishES: "view o set",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "view", Value: "view"},
						{Name: "set", Value: "set"},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "spam_messages",
					Description: "spam messages threshold",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "seuil messages spam",
						discordgo.EnglishUS: "spam messages threshold",
						discordgo.SpanishES: "umbral de mensajes spam",
					},
					Required: false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "spam_window",
					Description: "spam window seconds",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "fenetre spam (secondes)",
						discordgo.EnglishUS: "spam window seconds",
						discordgo.SpanishES: "ventana spam (segundos)",
					},
					Required: false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "raid_joins",
					Description: "raid joins threshold",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "seuil d'arrivees raid",
						discordgo.EnglishUS: "raid joins threshold",
						discordgo.SpanishES: "umbral de entradas raid",
					},
					Required: false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "raid_window",
					Description: "raid window seconds",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "fenetre raid (secondes)",
						discordgo.EnglishUS: "raid window seconds",
						discordgo.SpanishES: "ventana raid (segundos)",
					},
					Required: false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "phishing_risk",
					Description: "phishing risk points",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "points de risque phishing",
						discordgo.EnglishUS: "phishing risk points",
						discordgo.SpanishES: "puntos de riesgo phishing",
					},
					Required: false,
				},
			},
		},
		{
			Name:        "domain",
			Description: "Manage domain lists",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Gerer les listes de domaines",
				discordgo.EnglishUS: "Manage domain lists",
				discordgo.SpanishES: "Administrar listas de dominios",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "list",
					Description: "allow or block",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "allow ou block",
						discordgo.EnglishUS: "allow or block",
						discordgo.SpanishES: "allow o block",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "allow", Value: "allow"},
						{Name: "block", Value: "block"},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "action",
					Description: "add, remove, list",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "add, remove, list",
						discordgo.EnglishUS: "add, remove, list",
						discordgo.SpanishES: "add, remove, list",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "add", Value: "add"},
						{Name: "remove", Value: "remove"},
						{Name: "list", Value: "list"},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "domain",
					Description: "domain name",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "nom de domaine",
						discordgo.EnglishUS: "domain name",
						discordgo.SpanishES: "nombre de dominio",
					},
					Required: false,
				},
			},
		},
		{
			Name:        "report",
			Description: "Security report",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Rapport de securite",
				discordgo.EnglishUS: "Security report",
				discordgo.SpanishES: "Informe de seguridad",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "period",
					Description: "day or week",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "jour ou semaine",
						discordgo.EnglishUS: "day or week",
						discordgo.SpanishES: "dia o semana",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "day", Value: "day"},
						{Name: "week", Value: "week"},
					},
				},
			},
		},
		{
			Name:        "language",
			Description: "Set interface language",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Definir la langue de l'interface",
				discordgo.EnglishUS: "Set interface language",
				discordgo.SpanishES: "Definir el idioma de la interfaz",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "value",
					Description: "fr, en, es",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "fr, en, es",
						discordgo.EnglishUS: "fr, en, es",
						discordgo.SpanishES: "fr, en, es",
					},
					Required: false,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "fr", Value: "fr"},
						{Name: "en", Value: "en"},
						{Name: "es", Value: "es"},
					},
				},
			},
		},
		{
			Name:        "test",
			Description: "Simulate a security signal",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Simuler un signal de securite",
				discordgo.EnglishUS: "Simulate a security signal",
				discordgo.SpanishES: "Simular una senal de seguridad",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "scenario",
					Description: "spam, phishing, raid, or risk",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "spam, phishing, raid ou risk",
						discordgo.EnglishUS: "spam, phishing, raid, or risk",
						discordgo.SpanishES: "spam, phishing, raid o risk",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "spam", Value: "spam"},
						{Name: "phishing", Value: "phishing"},
						{Name: "raid", Value: "raid"},
						{Name: "risk", Value: "risk"},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "points",
					Description: "risk points for scenario=risk",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "points de risque pour scenario=risk",
						discordgo.EnglishUS: "risk points for scenario=risk",
						discordgo.SpanishES: "puntos de riesgo para scenario=risk",
					},
					Required: false,
				},
			},
		},
		{
			Name:        "logs",
			Description: "Set security log channel",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Definir le salon des logs",
				discordgo.EnglishUS: "Set security log channel",
				discordgo.SpanishES: "Definir canal de logs",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionChannel,
					Name:        "channel",
					Description: "admin-only channel",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "salon admin-only",
						discordgo.EnglishUS: "admin-only channel",
						discordgo.SpanishES: "canal solo admins",
					},
					Required: false,
				},
			},
		},
		{
			Name:        "risk",
			Description: "Manage risk scores",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Gerer les scores de risque",
				discordgo.EnglishUS: "Manage risk scores",
				discordgo.SpanishES: "Gestionar puntajes de riesgo",
			},
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "action",
					Description: "reset",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "reset",
						discordgo.EnglishUS: "reset",
						discordgo.SpanishES: "reset",
					},
					Required: true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "reset", Value: "reset"},
					},
				},
				{
					Type:        discordgo.ApplicationCommandOptionUser,
					Name:        "user",
					Description: "target user",
					DescriptionLocalizations: map[discordgo.Locale]string{
						discordgo.French:    "utilisateur cible",
						discordgo.EnglishUS: "target user",
						discordgo.SpanishES: "usuario objetivo",
					},
					Required: false,
				},
			},
		},
		{
			Name:        "verify",
			Description: "Verification flow",
			DescriptionLocalizations: &map[discordgo.Locale]string{
				discordgo.French:    "Flux de verification",
				discordgo.EnglishUS: "Verification flow",
				discordgo.SpanishES: "Flujo de verificacion",
			},
		},
	}

	appID := b.session.State.User.ID
	existing, err := b.session.ApplicationCommands(appID, "")
	if err != nil {
		for _, cmd := range commands {
			if _, err := b.session.ApplicationCommandCreate(appID, "", cmd); err != nil {
				return err
			}
		}
		return nil
	}

	existingByName := make(map[string]*discordgo.ApplicationCommand)
	for _, cmd := range existing {
		existingByName[cmd.Name] = cmd
	}

	desired := make(map[string]struct{})
	for _, cmd := range commands {
		desired[cmd.Name] = struct{}{}
		if current, ok := existingByName[cmd.Name]; ok {
			if _, err := b.session.ApplicationCommandEdit(appID, "", current.ID, cmd); err != nil {
				return err
			}
			continue
		}
		if _, err := b.session.ApplicationCommandCreate(appID, "", cmd); err != nil {
			return err
		}
	}

	for _, cmd := range existing {
		if _, ok := desired[cmd.Name]; ok {
			continue
		}
		_ = b.session.ApplicationCommandDelete(appID, "", cmd.ID)
	}

	for _, guild := range b.session.State.Guilds {
		if guild == nil {
			continue
		}
		guildID := guild.ID
		guildCmds, err := b.session.ApplicationCommands(appID, guildID)
		if err != nil {
			continue
		}
		for _, cmd := range guildCmds {
			if _, ok := desired[cmd.Name]; ok {
				continue
			}
			_ = b.session.ApplicationCommandDelete(appID, guildID, cmd.ID)
		}
	}
	return nil
}
