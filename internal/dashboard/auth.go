package dashboard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"sentinel-adaptive/internal/storage"

	"golang.org/x/oauth2"
)

type discordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
}

type discordGuild struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	Permissions int64  `json:"permissions"`
	Owner       bool   `json:"owner"`
}

func generateState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	url := s.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	// Verify CSRF state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: "", Path: "/", MaxAge: -1})

	// Exchange code
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Redirect(w, r, "/login?error=no_code", http.StatusFound)
		return
	}
	token, err := s.oauth2.Exchange(r.Context(), code)
	if err != nil {
		s.logger.Sugar().Warnf("oauth exchange: %v", err)
		http.Redirect(w, r, "/login?error=oauth", http.StatusFound)
		return
	}

	// Fetch Discord user info
	client := s.oauth2.Client(r.Context(), token)
	dUser, err := fetchDiscordUser(client)
	if err != nil {
		http.Redirect(w, r, "/login?error=api", http.StatusFound)
		return
	}

	// Fetch Discord guilds (best effort)
	dGuilds, _ := fetchDiscordGuilds(client)
	guildsJSON, _ := json.Marshal(dGuilds)

	now := time.Now()
	webUser := storage.WebUser{
		UserID:        dUser.ID,
		Username:      dUser.Username,
		Discriminator: dUser.Discriminator,
		Avatar:        dUser.Avatar,
		Email:         dUser.Email,
		GuildsJSON:    string(guildsJSON),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.store.UpsertWebUser(r.Context(), webUser); err != nil {
		s.logger.Sugar().Errorf("upsert user: %v", err)
		http.Redirect(w, r, "/login?error=db", http.StatusFound)
		return
	}

	sessionToken, err := s.createSession(r.Context(), dUser.ID)
	if err != nil {
		http.Redirect(w, r, "/login?error=session", http.StatusFound)
		return
	}

	s.setSessionCookie(w, sessionToken)
	http.Redirect(w, r, "/app", http.StatusFound)
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	token := s.getSessionToken(r)
	if token != "" {
		_ = s.store.DeleteSession(r.Context(), token)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func fetchDiscordUser(client *http.Client) (*discordUser, error) {
	resp, err := client.Get("https://discord.com/api/users/@me")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var u discordUser
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("decode discord user: %w", err)
	}
	if u.ID == "" {
		return nil, fmt.Errorf("empty user id from Discord API")
	}
	return &u, nil
}

func fetchDiscordGuilds(client *http.Client) ([]discordGuild, error) {
	resp, err := client.Get("https://discord.com/api/users/@me/guilds")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var guilds []discordGuild
	if err := json.Unmarshal(body, &guilds); err != nil {
		return nil, fmt.Errorf("decode guilds: %w", err)
	}
	return guilds, nil
}
