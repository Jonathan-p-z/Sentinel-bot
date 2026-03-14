package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"sentinel-adaptive/internal/storage"
)

const (
	sessionCookieName = "bastion_sess"
	sessionDuration   = 7 * 24 * time.Hour
)

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) createSession(ctx context.Context, userID string) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	sess := storage.WebSession{
		Token:     token,
		UserID:    userID,
		ExpiresAt: now.Add(sessionDuration),
		CreatedAt: now,
	}
	if err := s.store.CreateSession(ctx, sess); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionDuration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func (s *Server) getSessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *Server) loadUser(r *http.Request) (*storage.WebUser, error) {
	token := s.getSessionToken(r)
	if token == "" {
		return nil, nil
	}
	sess, err := s.store.GetSession(r.Context(), token)
	if err != nil || sess == nil {
		return nil, err
	}
	return s.store.GetWebUser(r.Context(), sess.UserID)
}
