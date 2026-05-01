package dashboard

import (
	"net/http"
	"strings"
)

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.loadUser(r)
		if err != nil || user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := r.Context()
		ctx = withUser(ctx, user)
		ctx = withLang(ctx, detectLang(r))
		r = r.WithContext(ctx)
		next(w, r)
	}
}

// requireAdmin protects the admin panel with three layers:
//  1. Valid session + Discord ID matches ADMIN_DISCORD_USER_ID
//  2. IP allowlist — if ADMIN_ALLOWED_IPS is set, the request IP must be listed
//  3. Returns 404 (not 403) so the page appears non-existent to outsiders
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user := currentUser(r)
		if user == nil || user.UserID != s.cfg.AdminDiscordUserID {
			http.NotFound(w, r)
			return
		}
		if s.cfg.AdminAllowedIPs != "" {
			ip := clientIP(r)
			allowed := false
			for _, allowedIP := range strings.Split(s.cfg.AdminAllowedIPs, ",") {
				if strings.TrimSpace(allowedIP) == ip {
					allowed = true
					break
				}
			}
			if !allowed {
				http.NotFound(w, r)
				return
			}
		}
		next(w, r)
	})
}
