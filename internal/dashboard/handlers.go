package dashboard

import (
	"encoding/json"
	"net/http"
	"time"

	"sentinel-adaptive/internal/storage"
)

// ── Page data types ───────────────────────────────────

type pageData struct {
	User        *storage.WebUser
	IsAdmin     bool
	CurrentPage string
	GuildID     string
}

type landingData struct{}

type loginData struct {
	Error string
}

type guildInfo struct {
	ID         string
	Name       string
	Icon       string
	HasBastion bool
	Plan       string
}

type appHomeData struct {
	pageData
	Guilds []guildInfo
}

type guildViewData struct {
	pageData
	Guild guildInfo
}

type auditViewData struct {
	guildViewData
	Logs  []storage.AuditLog
	Since string
}

type riskViewData struct {
	guildViewData
	CritLogs []storage.AuditLog
	WarnLogs []storage.AuditLog
}

type moduleStatus struct {
	Name        string
	Description string
	Enabled     bool
	Icon        string
}

type modulesViewData struct {
	guildViewData
	Modules []moduleStatus
}

type configViewData struct {
	guildViewData
	TicketCategoryID string
	Saved            bool
	Error            string
}

type billingPlan struct {
	ID       string
	Name     string
	Price    string
	Period   string
	Features []string
	Current  bool
}

type billingData struct {
	pageData
	Subscriptions []storage.Subscription
	Plans         []billingPlan
}

type adminGuildInfo struct {
	ID          string
	Name        string
	Icon        string
	MemberCount int
	Plan        string
}

type adminData struct {
	pageData
	TotalGuilds int
	PlanCounts  map[string]int
	TotalUsers  int
	BotGuilds   []adminGuildInfo
}

// ── Helpers ───────────────────────────────────────────

func (s *Server) base(r *http.Request, page string) pageData {
	user := currentUser(r)
	isAdmin := user != nil && user.UserID == s.cfg.AdminDiscordUserID
	guildID := r.URL.Query().Get("id")
	return pageData{User: user, IsAdmin: isAdmin, CurrentPage: page, GuildID: guildID}
}

func (s *Server) getUserGuilds(user *storage.WebUser) []discordGuild {
	var guilds []discordGuild
	_ = json.Unmarshal([]byte(user.GuildsJSON), &guilds)
	return guilds
}

func (s *Server) resolveGuild(r *http.Request, user *storage.WebUser) (guildInfo, bool) {
	guildID := r.URL.Query().Get("id")
	if guildID == "" {
		return guildInfo{}, false
	}

	const manageServer = int64(0x20)
	const adminPerm = int64(0x8)

	// The guild must be in the user's Discord guild list AND the user must
	// have Manage Server, Administrator, or be the owner.
	guilds := s.getUserGuilds(user)
	var matched *discordGuild
	for i := range guilds {
		if guilds[i].ID == guildID {
			matched = &guilds[i]
			break
		}
	}
	if matched == nil {
		return guildInfo{}, false
	}
	if !matched.Owner && matched.Permissions&manageServer == 0 && matched.Permissions&adminPerm == 0 {
		return guildInfo{}, false
	}

	g := guildInfo{ID: guildID, Name: matched.Name, Icon: matched.Icon}
	// Check if Bastion is installed
	if s.discord != nil {
		if _, err := s.discord.State.Guild(guildID); err == nil {
			g.HasBastion = true
		}
	}
	// Get plan
	if sub, err := s.store.GetSubscription(r.Context(), guildID); err == nil && sub != nil {
		g.Plan = sub.Plan
	} else {
		g.Plan = "free"
	}
	return g, true
}

var billingPlans = []billingPlan{
	{
		ID:     "free",
		Name:   "Free",
		Price:  "0",
		Period: "",
		Features: []string{
			"1 serveur",
			"Modules de base (antispam, antiraid, antiphishing)",
			"Logs 7 jours",
			"5 règles personnalisées",
		},
	},
	{
		ID:     "pro",
		Name:   "Pro",
		Price:  "4.99",
		Period: "/mois",
		Features: []string{
			"3 serveurs",
			"Tous les modules",
			"Logs 30 jours",
			"Dashboard complet",
			"Support prioritaire",
		},
	},
	{
		ID:     "business",
		Name:   "Business",
		Price:  "14.99",
		Period: "/mois",
		Features: []string{
			"10 serveurs",
			"Tout Pro inclus",
			"Behaviour Graph",
			"File Scanner",
			"API Access",
			"Logs 90 jours",
		},
	},
	{
		ID:     "enterprise",
		Name:   "Enterprise",
		Price:  "49.99",
		Period: "/mois",
		Features: []string{
			"Serveurs illimités",
			"Tout Business inclus",
			"Self-host option",
			"White-label",
			"Logs illimités",
			"Support dédié",
		},
	},
}

// ── Handlers ──────────────────────────────────────────

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderStandalone(w, "landing", landingData{})
}

func (s *Server) handleLegal(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, "legal", s.base(r, "legal"))
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Already logged in → go to app
	user, _ := s.loadUser(r)
	if user != nil {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}
	errParam := r.URL.Query().Get("error")
	errMsg := ""
	switch errParam {
	case "oauth":
		errMsg = "Erreur lors de l'authentification Discord."
	case "api":
		errMsg = "Impossible de récupérer les informations de votre compte Discord."
	case "db", "session":
		errMsg = "Erreur interne. Veuillez réessayer."
	}
	s.renderStandalone(w, "login", loginData{Error: errMsg})
}

func (s *Server) handleAppHome(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	dGuilds := s.getUserGuilds(user)

	var guilds []guildInfo
	for _, dg := range dGuilds {
		// Only show guilds where user has MANAGE_SERVER (0x20) or ADMINISTRATOR (0x8)
		const manageServer = int64(0x20)
		const admin = int64(0x8)
		if dg.Permissions&manageServer == 0 && dg.Permissions&admin == 0 && !dg.Owner {
			continue
		}
		g := guildInfo{
			ID:   dg.ID,
			Name: dg.Name,
			Icon: dg.Icon,
		}
		if s.discord != nil {
			if _, err := s.discord.State.Guild(dg.ID); err == nil {
				g.HasBastion = true
			}
		}
		if sub, err := s.store.GetSubscription(r.Context(), dg.ID); err == nil && sub != nil {
			g.Plan = sub.Plan
		} else {
			g.Plan = "free"
		}
		guilds = append(guilds, g)
	}

	s.renderPage(w, "app_home", appHomeData{
		pageData: s.base(r, "home"),
		Guilds:   guilds,
	})
}

func (s *Server) handleGuildOverview(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	guild, ok := s.resolveGuild(r, user)
	if !ok {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}
	s.renderPage(w, "guild", guildViewData{
		pageData: s.base(r, "guild"),
		Guild:    guild,
	})
}

func (s *Server) handleGuildAudit(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	guild, ok := s.resolveGuild(r, user)
	if !ok {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}

	sinceParam := r.URL.Query().Get("since")
	since := time.Now().AddDate(0, 0, -7)
	sinceLabel := "7 derniers jours"
	switch sinceParam {
	case "1d":
		since = time.Now().AddDate(0, 0, -1)
		sinceLabel = "Dernières 24h"
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
		sinceLabel = "30 derniers jours"
	case "7d":
	default:
		sinceParam = "7d"
	}

	logs, err := s.store.ListAuditLogs(r.Context(), guild.ID, since)
	if err != nil {
		s.logger.Sugar().Errorf("list audit logs: %v", err)
		logs = nil
	}

	s.renderPage(w, "audit", auditViewData{
		guildViewData: guildViewData{pageData: s.base(r, "audit"), Guild: guild},
		Logs:          logs,
		Since:         sinceLabel,
	})
}

func (s *Server) handleGuildRisk(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	guild, ok := s.resolveGuild(r, user)
	if !ok {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}

	since := time.Now().AddDate(0, 0, -7)
	allLogs, err := s.store.ListAuditLogs(r.Context(), guild.ID, since)
	if err != nil {
		allLogs = nil
	}

	var critLogs, warnLogs []storage.AuditLog
	for _, l := range allLogs {
		switch l.Level {
		case "CRIT":
			if len(critLogs) < 20 {
				critLogs = append(critLogs, l)
			}
		case "WARN":
			if len(warnLogs) < 20 {
				warnLogs = append(warnLogs, l)
			}
		}
	}

	s.renderPage(w, "risk", riskViewData{
		guildViewData: guildViewData{pageData: s.base(r, "risk"), Guild: guild},
		CritLogs:      critLogs,
		WarnLogs:      warnLogs,
	})
}

func (s *Server) handleGuildModules(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	guild, ok := s.resolveGuild(r, user)
	if !ok {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}

	// Get guild settings to show module status
	modules := []moduleStatus{
		{Name: "Anti-Spam", Description: "Détecte les rafales de messages et limite le spam.", Enabled: true, Icon: "shield"},
		{Name: "Anti-Raid", Description: "Détecte les afflux de nouveaux membres et déclenche le lockdown.", Enabled: true, Icon: "users"},
		{Name: "Anti-Phishing", Description: "Bloque les liens suspects, de phishing et de nitro scam.", Enabled: true, Icon: "link"},
		{Name: "Anti-Nuke", Description: "Empêche la destruction massive de canaux, rôles et bans.", Enabled: true, Icon: "bomb"},
		{Name: "Behaviour Graph", Description: "Analyse comportementale avancée des membres.", Enabled: false, Icon: "activity"},
		{Name: "File Scanner", Description: "Analyse les pièces jointes à la recherche de malwares.", Enabled: false, Icon: "file"},
		{Name: "Verification", Description: "Système de vérification pour les nouveaux membres.", Enabled: false, Icon: "check"},
	}

	s.renderPage(w, "modules", modulesViewData{
		guildViewData: guildViewData{pageData: s.base(r, "modules"), Guild: guild},
		Modules:       modules,
	})
}

func (s *Server) handleGuildConfig(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	guild, ok := s.resolveGuild(r, user)
	if !ok {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}

	defaults := storage.GuildSettings{}
	settings, err := s.store.GetGuildSettings(r.Context(), guild.ID, defaults)
	if err != nil {
		s.logger.Sugar().Errorw("get guild settings", "err", err)
	}

	data := configViewData{
		guildViewData:    guildViewData{pageData: s.base(r, "config"), Guild: guild},
		TicketCategoryID: settings.TicketCategoryID,
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			data.Error = "Erreur lors de la lecture du formulaire."
			s.renderPage(w, "config", data)
			return
		}
		categoryID := r.FormValue("ticket_category_id")
		if err := s.store.SetTicketCategoryID(r.Context(), guild.ID, categoryID); err != nil {
			s.logger.Sugar().Errorw("set ticket category", "err", err)
			data.Error = "Erreur lors de la sauvegarde."
			s.renderPage(w, "config", data)
			return
		}
		data.TicketCategoryID = categoryID
		data.Saved = true
	}

	s.renderPage(w, "config", data)
}

func (s *Server) handleBilling(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	subs, err := s.store.ListUserSubscriptions(r.Context(), user.UserID)
	if err != nil {
		subs = nil
	}

	// Mark current plan on each billing plan card
	currentPlan := "free"
	if len(subs) > 0 {
		currentPlan = subs[0].Plan
	}
	plans := make([]billingPlan, len(billingPlans))
	copy(plans, billingPlans)
	for i := range plans {
		plans[i].Current = plans[i].ID == currentPlan
	}

	s.renderPage(w, "billing", billingData{
		pageData:      s.base(r, "billing"),
		Subscriptions: subs,
		Plans:         plans,
	})
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	totalGuilds, _ := s.store.CountGuildSettings(r.Context())
	planCounts, err := s.store.CountSubscriptionsByPlan(r.Context())
	if err != nil {
		planCounts = map[string]int{}
	}

	var botGuilds []adminGuildInfo
	if s.discord != nil {
		for _, g := range s.discord.State.Guilds {
			info := adminGuildInfo{
				ID:          g.ID,
				Name:        g.Name,
				Icon:        g.Icon,
				MemberCount: g.MemberCount,
			}
			if sub, err := s.store.GetSubscription(r.Context(), g.ID); err == nil && sub != nil {
				info.Plan = sub.Plan
			} else {
				info.Plan = "free"
			}
			botGuilds = append(botGuilds, info)
		}
	}

	s.renderPage(w, "admin", adminData{
		pageData:    s.base(r, "admin"),
		TotalGuilds: totalGuilds,
		PlanCounts:  planCounts,
		BotGuilds:   botGuilds,
	})
}
