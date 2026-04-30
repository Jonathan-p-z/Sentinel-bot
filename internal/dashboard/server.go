package dashboard

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"time"

	"sentinel-adaptive/internal/billing"
	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/storage"
	"sentinel-adaptive/web"

	"github.com/bwmarrin/discordgo"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

//go:embed templates
var tmplFS embed.FS

type Server struct {
	cfg     config.Config
	store   *storage.Store
	billing *billing.BillingService
	discord *discordgo.Session
	logger  *zap.Logger
	mux     *http.ServeMux
	oauth2  *oauth2.Config
	rl      *rateLimiter
}

type contextKey string

const ctxUser contextKey = "user"

func New(cfg config.Config, store *storage.Store, discord *discordgo.Session, logger *zap.Logger) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		store:   store,
		discord: discord,
		logger:  logger,
		mux:     http.NewServeMux(),
		rl:      newRateLimiter(),
		oauth2: &oauth2.Config{
			ClientID:     cfg.Dashboard.DiscordClientID,
			ClientSecret: cfg.Dashboard.DiscordClientSecret,
			RedirectURL:  cfg.Dashboard.RedirectURL,
			Scopes:       []string{"identify", "guilds", "email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://discord.com/api/oauth2/authorize",
				TokenURL: "https://discord.com/api/oauth2/token",
			},
		},
	}
	s.billing = billing.New(&s.cfg, store)
	s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.securityHeaders(w)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	h.Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' https://cdnjs.cloudflare.com 'sha256-XusCoAI/06CL+91xmnNxw3nQPhfWTZ7hPxLF9CNwUhM='; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"img-src 'self' https://cdn.discordapp.com data:; "+
			"font-src 'self' https://fonts.gstatic.com; "+
			"connect-src 'self'; "+
			"frame-ancestors 'none'")
}

func init() {
	mime.AddExtensionType(".css", "text/css; charset=utf-8")
	mime.AddExtensionType(".js", "application/javascript; charset=utf-8")
}

func (s *Server) routes() {
	staticFS, err := fs.Sub(web.StaticFS, "static")
	if err != nil {
		panic(err)
	}
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	site := http.FileServer(http.Dir("web/site"))
	siteHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;")
		site.ServeHTTP(w, r)
	})
	s.mux.Handle("/_next/", siteHandler)
	s.mux.Handle("/", siteHandler)
	s.mux.HandleFunc("/legal", s.handleLegal)
	s.mux.HandleFunc("/login", s.handleLoginPage)

	// OAuth2 — rate limited
	s.mux.HandleFunc("/auth/login", s.limitAuth(s.handleAuthLogin))
	s.mux.HandleFunc("/auth/callback", s.limitAuth(s.handleAuthCallback))
	s.mux.HandleFunc("/auth/logout", s.handleAuthLogout)

	// Stripe webhook — no auth, Stripe signs requests itself
	s.mux.HandleFunc("/billing/webhook", s.billing.WebhookHandler())

	s.mux.HandleFunc("/app", s.requireAuth(s.handleAppHome))
	s.mux.HandleFunc("/app/guild", s.requireAuth(s.handleGuildOverview))
	s.mux.HandleFunc("/app/guild/audit", s.requireAuth(s.handleGuildAudit))
	s.mux.HandleFunc("/app/guild/risk", s.requireAuth(s.handleGuildRisk))
	s.mux.HandleFunc("/app/guild/modules", s.requireAuth(s.handleGuildModules))
	s.mux.HandleFunc("/app/guild/config", s.requireAuth(s.handleGuildConfig))
	s.mux.HandleFunc("/app/billing", s.requireAuth(s.handleBilling))
	s.mux.HandleFunc("/app/billing/checkout", s.requireAuth(s.handleBillingCheckout))
	s.mux.HandleFunc("/app/billing/cancel", s.requireAuth(s.handleBillingCancel))

	// Admin — requires admin user + optional secret path
	adminPath := "/admin"
	if s.cfg.AdminPathSecret != "" {
		adminPath = "/admin/" + s.cfg.AdminPathSecret
	}
	s.mux.HandleFunc(adminPath, s.requireAdmin(s.handleAdmin))
}

func (s *Server) funcMap() template.FuncMap {
	return template.FuncMap{
		"avatarURL":    avatarURL,
		"guildIconURL": guildIconURL,
		"timeAgo":      timeAgo,
		"formatTime":   formatTime,
		"badgeClass":   badgeClass,
		"planLabel":    planLabel,
		"planBadge":    planBadge,
		"inviteURL": func() string {
			return discordInviteURL(s.cfg.Dashboard.DiscordClientID)
		},
		"isAdmin": func(userID string) bool {
			return userID == s.cfg.AdminDiscordUserID
		},
		"safe": func(s string) template.HTML { return template.HTML(s) },
		"add": func(a, b int) int { return a + b },
		"mul": func(a, b int) int { return a * b },
	}
}

func (s *Server) renderPage(w http.ResponseWriter, page string, data interface{}) {
	t, err := template.New("").Funcs(s.funcMap()).ParseFS(tmplFS,
		"templates/layout.html",
		"templates/"+page+".html",
	)
	if err != nil {
		s.logger.Error("template parse error", zap.String("page", page), zap.Error(err))
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("template execute error", zap.String("page", page), zap.Error(err))
	}
}

func (s *Server) renderStandalone(w http.ResponseWriter, page string, data interface{}) {
	t, err := template.New("").Funcs(s.funcMap()).ParseFS(tmplFS, "templates/"+page+".html")
	if err != nil {
		s.logger.Error("template parse error", zap.String("page", page), zap.Error(err))
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, page, data); err != nil {
		s.logger.Error("template execute error", zap.String("page", page), zap.Error(err))
	}
}

func avatarURL(userID, avatar string) string {
	if avatar == "" {
		return "https://cdn.discordapp.com/embed/avatars/0.png"
	}
	return fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.webp?size=64", userID, avatar)
}

func guildIconURL(guildID, icon string) string {
	if icon == "" {
		return ""
	}
	return fmt.Sprintf("https://cdn.discordapp.com/icons/%s/%s.webp?size=64", guildID, icon)
}

func timeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func formatTime(t time.Time) string {
	return t.Format("Jan 02 · 15:04")
}

func badgeClass(level string) string {
	switch level {
	case "CRIT":
		return "badge-danger"
	case "WARN":
		return "badge-warning"
	default:
		return "badge-info"
	}
}

func planLabel(plan string) string {
	switch plan {
	case "pro":
		return "Pro"
	case "business":
		return "Business"
	case "enterprise":
		return "Enterprise"
	default:
		return "Free"
	}
}

func planBadge(plan string) string {
	switch plan {
	case "pro":
		return "badge-accent"
	case "business":
		return "badge-success"
	case "enterprise":
		return "badge-gold"
	default:
		return "badge-muted"
	}
}

func discordInviteURL(clientID string) string {
	if clientID == "" {
		return "#"
	}
	return fmt.Sprintf(
		"https://discord.com/api/oauth2/authorize?client_id=%s&permissions=8&scope=bot%%20applications.commands",
		clientID,
	)
}

func currentUser(r *http.Request) *storage.WebUser {
	u, _ := r.Context().Value(ctxUser).(*storage.WebUser)
	return u
}

func withUser(ctx context.Context, u *storage.WebUser) context.Context {
	return context.WithValue(ctx, ctxUser, u)
}
