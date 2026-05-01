package dashboard

import (
	"encoding/json"
	"net/http"
	"time"

	"sentinel-adaptive/internal/storage"

	"go.uber.org/zap"
)

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
	PriceID  string
}

type billingData struct {
	pageData
	CurrentTier string
	PeriodEnd   time.Time
	Plans       []billingPlan
	Success     bool
	Canceled    bool
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

	// user must have manage-server/admin/owner on this guild
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
	if s.discord != nil {
		if _, err := s.discord.State.Guild(guildID); err == nil {
			g.HasBastion = true
		}
	}
	if sub, err := s.store.GetSubscription(r.Context(), guildID); err == nil && sub != nil {
		g.Plan = sub.Tier
		s.logger.Info("resolveGuild: subscription found",
			zap.String("guild_id", guildID),
			zap.String("tier", sub.Tier),
			zap.String("status", sub.Status),
		)
	} else {
		g.Plan = "free"
		s.logger.Warn("resolveGuild: subscription not found or error, defaulting to free",
			zap.String("guild_id", guildID),
			zap.Error(err),
			zap.Bool("sub_nil", sub == nil),
		)
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
			"billing.plan.free.feature.0",
			"billing.plan.free.feature.1",
			"billing.plan.free.feature.2",
			"billing.plan.free.feature.3",
		},
	},
	{
		ID:     "pro",
		Name:   "Pro",
		Price:  "4.99",
		Period: "billing.period.monthly",
		Features: []string{
			"billing.plan.pro.feature.0",
			"billing.plan.pro.feature.1",
			"billing.plan.pro.feature.2",
			"billing.plan.pro.feature.3",
			"billing.plan.pro.feature.4",
		},
	},
	{
		ID:     "business",
		Name:   "Business",
		Price:  "14.99",
		Period: "billing.period.monthly",
		Features: []string{
			"billing.plan.business.feature.0",
			"billing.plan.business.feature.1",
			"billing.plan.business.feature.2",
			"billing.plan.business.feature.3",
			"billing.plan.business.feature.4",
			"billing.plan.business.feature.5",
		},
	},
	{
		ID:     "enterprise",
		Name:   "Enterprise",
		Price:  "49.99",
		Period: "billing.period.monthly",
		Features: []string{
			"billing.plan.enterprise.feature.0",
			"billing.plan.enterprise.feature.1",
			"billing.plan.enterprise.feature.2",
			"billing.plan.enterprise.feature.3",
			"billing.plan.enterprise.feature.4",
			"billing.plan.enterprise.feature.5",
		},
	},
}

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.renderStandalone(w, r, "landing", landingData{})
}

func (s *Server) handleLegal(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, "legal", s.base(r, "legal"))
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	user, _ := s.loadUser(r)
	if user != nil {
		http.Redirect(w, r, "/app", http.StatusFound)
		return
	}
	lang := detectLang(r)
	errParam := r.URL.Query().Get("error")
	errMsg := ""
	switch errParam {
	case "oauth":
		errMsg = s.i18n.T(lang, "auth.error.oauth")
	case "api":
		errMsg = s.i18n.T(lang, "auth.error.api")
	case "db", "session":
		errMsg = s.i18n.T(lang, "auth.error.db")
	}
	s.renderStandalone(w, r, "login", loginData{Error: errMsg})
}

func (s *Server) handleAppHome(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	dGuilds := s.getUserGuilds(user)

	var guilds []guildInfo
	for _, dg := range dGuilds {
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
			g.Plan = sub.Tier
		} else {
			g.Plan = "free"
		}
		guilds = append(guilds, g)
	}

	s.renderPage(w, r, "app_home", appHomeData{
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
	s.renderPage(w, r, "guild", guildViewData{
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
	sinceKey := "7d"
	switch sinceParam {
	case "1d":
		since = time.Now().AddDate(0, 0, -1)
		sinceKey = "1d"
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
		sinceKey = "30d"
	case "7d":
	default:
		sinceParam = "7d"
	}

	logs, err := s.store.ListAuditLogs(r.Context(), guild.ID, since)
	if err != nil {
		s.logger.Sugar().Errorf("list audit logs: %v", err)
		logs = nil
	}

	s.renderPage(w, r, "audit", auditViewData{
		guildViewData: guildViewData{pageData: s.base(r, "audit"), Guild: guild},
		Logs:          logs,
		Since:         sinceKey,
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

	s.renderPage(w, r, "risk", riskViewData{
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

	isPro := guild.Plan == "pro" || guild.Plan == "business" || guild.Plan == "enterprise"
	isBusiness := guild.Plan == "business" || guild.Plan == "enterprise"

	s.logger.Info("handleGuildModules: gating computed",
		zap.String("guild_id", guild.ID),
		zap.String("plan", guild.Plan),
		zap.Bool("is_pro", isPro),
		zap.Bool("is_business", isBusiness),
	)

	lang := currentLang(r)
	modules := []moduleStatus{
		{Name: "Anti-Spam", Description: s.i18n.T(lang, "modules.antispam.desc"), Enabled: true, Icon: "shield"},
		{Name: "Anti-Raid", Description: s.i18n.T(lang, "modules.antiraid.desc"), Enabled: true, Icon: "users"},
		{Name: "Anti-Phishing", Description: s.i18n.T(lang, "modules.antiphishing.desc"), Enabled: true, Icon: "link"},
		{Name: "Anti-Nuke", Description: s.i18n.T(lang, "modules.antinuke.desc"), Enabled: true, Icon: "bomb"},
		{Name: "Behaviour Graph", Description: s.i18n.T(lang, "modules.behaviour.desc"), Enabled: isBusiness, Icon: "activity"},
		{Name: "File Scanner", Description: s.i18n.T(lang, "modules.filescanner.desc"), Enabled: isBusiness, Icon: "file"},
		{Name: "Verification", Description: s.i18n.T(lang, "modules.verification.desc"), Enabled: isPro, Icon: "check"},
	}

	s.renderPage(w, r, "modules", modulesViewData{
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
			data.Error = s.i18n.T(currentLang(r), "config.error.parse_form")
			s.renderPage(w, r, "config", data)
			return
		}
		categoryID := r.FormValue("ticket_category_id")
		if err := s.store.SetTicketCategoryID(r.Context(), guild.ID, categoryID); err != nil {
			s.logger.Sugar().Errorw("set ticket category", "err", err)
			data.Error = s.i18n.T(currentLang(r), "config.error.save")
			s.renderPage(w, r, "config", data)
			return
		}
		data.TicketCategoryID = categoryID
		data.Saved = true
	}

	s.renderPage(w, r, "config", data)
}

func (s *Server) handleBilling(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	guildID := r.URL.Query().Get("id")

	currentTier := "free"
	var periodEnd time.Time

	if guildID != "" && s.userManagesGuild(user, guildID) {
		if sub, err := s.billing.GetSubscription(guildID); err == nil {
			currentTier = sub.Tier
			if sub.CurrentPeriodEnd != nil {
				periodEnd = *sub.CurrentPeriodEnd
			}
		}
	}

	plans := make([]billingPlan, len(billingPlans))
	copy(plans, billingPlans)
	for i := range plans {
		plans[i].Current = plans[i].ID == currentTier
		switch plans[i].ID {
		case "pro":
			plans[i].PriceID = s.cfg.Stripe.PriceIDPro
		case "business":
			plans[i].PriceID = s.cfg.Stripe.PriceIDBusiness
		case "enterprise":
			plans[i].PriceID = s.cfg.Stripe.PriceIDEnterprise
		}
	}

	s.renderPage(w, r, "billing", billingData{
		pageData:    s.base(r, "billing"),
		CurrentTier: currentTier,
		PeriodEnd:   periodEnd,
		Plans:       plans,
		Success:     r.URL.Query().Get("success") == "true",
		Canceled:    r.URL.Query().Get("canceled") == "true",
	})
}

func (s *Server) handleBillingCheckout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/app/billing", http.StatusSeeOther)
		return
	}
	user := currentUser(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	priceID := r.FormValue("price_id")
	guildID := r.FormValue("guild_id")
	if priceID == "" || guildID == "" || !s.userManagesGuild(user, guildID) {
		http.Redirect(w, r, "/app/billing?id="+guildID, http.StatusSeeOther)
		return
	}

	session, err := s.billing.CreateCheckoutSession(
		guildID, user.UserID, priceID,
		"https://dashboard-bastion.yaiito.fr/app/billing?success=true",
		"https://dashboard-bastion.yaiito.fr/app/billing?canceled=true",
	)
	if err != nil {
		s.logger.Sugar().Errorw("create checkout session", "err", err)
		http.Redirect(w, r, "/app/billing?id="+guildID+"&error=1", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, session.URL, http.StatusSeeOther)
}

func (s *Server) handleBillingCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/app/billing", http.StatusSeeOther)
		return
	}
	user := currentUser(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	guildID := r.FormValue("guild_id")
	if guildID == "" || !s.userManagesGuild(user, guildID) {
		http.Redirect(w, r, "/app/billing?id="+guildID, http.StatusSeeOther)
		return
	}

	if err := s.billing.CancelSubscription(guildID); err != nil {
		s.logger.Sugar().Errorw("cancel subscription", "guild_id", guildID, "err", err)
	}

	http.Redirect(w, r, "/app/billing?canceled=true&id="+guildID, http.StatusSeeOther)
}

func (s *Server) userManagesGuild(user *storage.WebUser, guildID string) bool {
	const manageServer = int64(0x20)
	const adminPerm = int64(0x8)
	for _, g := range s.getUserGuilds(user) {
		if g.ID != guildID {
			continue
		}
		return g.Owner || g.Permissions&manageServer != 0 || g.Permissions&adminPerm != 0
	}
	return false
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	totalGuilds, _ := s.store.CountGuildSettings(r.Context())
	planCounts, err := s.store.CountSubscriptionsByPlan(r.Context())
	if err != nil {
		planCounts = map[string]int{}
	}

	var botGuilds []adminGuildInfo
	if s.discord != nil {
		guildIDs := make([]string, 0, len(s.discord.State.Guilds))
		for _, g := range s.discord.State.Guilds {
			guildIDs = append(guildIDs, g.ID)
		}
		tiers, _ := s.store.GetTiersByGuildIDs(r.Context(), guildIDs)
		for _, g := range s.discord.State.Guilds {
			tier := tiers[g.ID]
			if tier == "" {
				tier = "free"
			}
			botGuilds = append(botGuilds, adminGuildInfo{
				ID:          g.ID,
				Name:        g.Name,
				Icon:        g.Icon,
				MemberCount: g.MemberCount,
				Plan:        tier,
			})
		}
	}

	s.renderPage(w, r, "admin", adminData{
		pageData:    s.base(r, "admin"),
		TotalGuilds: totalGuilds,
		PlanCounts:  planCounts,
		BotGuilds:   botGuilds,
	})
}
