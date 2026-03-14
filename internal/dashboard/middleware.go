package dashboard

import (
	"net/http"
)

// requireAuth wraps a handler and redirects to /login if no valid session.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, err := s.loadUser(r)
		if err != nil || user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		r = r.WithContext(withUser(r.Context(), user))
		next(w, r)
	}
}

// requireAdmin wraps a handler and returns 403 if the user is not the admin.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		user := currentUser(r)
		if user == nil || user.UserID != s.cfg.AdminDiscordUserID {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}
