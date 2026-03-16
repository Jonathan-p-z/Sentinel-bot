package verification

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/rand"
	"strings"
	"sync"
	"time"

	"sentinel-adaptive/internal/config"
	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/storage"

	"github.com/bwmarrin/discordgo"
	xfont "golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const (
	// captchaCharset excludes visually ambiguous characters (0/O, 1/I/l).
	captchaCharset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	captchaCodeLen = 6
	maxAttempts    = 3
)

// activeSession holds the in-memory state for an ongoing onboarding flow.
type activeSession struct {
	guildID string
	state   string // "captcha" | "quiz"
}

type Module struct {
	cfg   config.OnboardingConfig
	store *storage.Store
	audit *audit.Logger

	mu       sync.Mutex
	sessions map[string]*activeSession // userID → state
}

func New(cfg config.OnboardingConfig, store *storage.Store, auditLogger *audit.Logger) *Module {
	return &Module{
		cfg:      cfg,
		store:    store,
		audit:    auditLogger,
		sessions: make(map[string]*activeSession),
	}
}

// HandleVerify satisfies the existing bot interface for the /verify slash command.
func (m *Module) HandleVerify(ctx context.Context) {
	_ = ctx
}

// HandleMemberAdd initiates the onboarding flow for a newly joined member.
func (m *Module) HandleMemberAdd(ctx context.Context, session *discordgo.Session, event *discordgo.GuildMemberAdd) {
	if !m.cfg.Enabled || event.Member == nil || event.Member.User == nil {
		return
	}

	guildID := event.GuildID
	user := event.Member.User

	// Nothing to verify: grant role immediately.
	if !m.cfg.CaptchaEnabled && !m.cfg.QuizEnabled {
		m.grantRole(session, guildID, user.ID)
		return
	}

	dmChannel, err := session.UserChannelCreate(user.ID)
	if err != nil {
		m.audit.Log(ctx, audit.LevelWarn, guildID, user.ID, "onboarding_dm_fail", err.Error())
		return
	}

	timeout := time.Duration(m.cfg.TimeoutMinutes) * time.Minute
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	expiresAt := time.Now().Add(timeout)

	var code string
	initialState := "quiz"

	if m.cfg.CaptchaEnabled {
		initialState = "captcha"
		code = generateCode()

		pngData, err := generateCaptchaPNG(code)
		if err != nil {
			m.audit.Log(ctx, audit.LevelWarn, guildID, user.ID, "onboarding_captcha_gen_fail", err.Error())
			return
		}

		msg := fmt.Sprintf(
			"Bienvenue sur le serveur ! Recopie le code visible sur l'image pour accéder au serveur. "+
				"Tu as **%d minute(s)**.", m.cfg.TimeoutMinutes)
		_, err = session.ChannelMessageSendComplex(dmChannel.ID, &discordgo.MessageSend{
			Content: msg,
			Files: []*discordgo.File{{
				Name:        "captcha.png",
				ContentType: "image/png",
				Reader:      bytes.NewReader(pngData),
			}},
		})
		if err != nil {
			m.audit.Log(ctx, audit.LevelWarn, guildID, user.ID, "onboarding_dm_send_fail", err.Error())
			return
		}
	} else {
		// Skip captcha, go straight to quiz.
		_, _ = session.ChannelMessageSend(dmChannel.ID, fmt.Sprintf(
			"Bienvenue ! Réponds à la question suivante pour accéder au serveur (tu as **%d minute(s)**) :\n\n**%s**",
			m.cfg.TimeoutMinutes, m.cfg.QuizQuestion))
	}

	_ = m.store.UpsertOnboardingSession(ctx, storage.OnboardingSession{
		GuildID:     guildID,
		UserID:      user.ID,
		CaptchaCode: code,
		Attempts:    0,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Status:      "pending_" + initialState,
	})

	m.mu.Lock()
	m.sessions[user.ID] = &activeSession{guildID: guildID, state: initialState}
	m.mu.Unlock()

	go m.scheduleExpiry(ctx, session, guildID, user.ID, timeout)
}

// HandleDM processes a direct-message reply from a user in an active onboarding
// session. Returns true when the message is consumed (caller must return early).
func (m *Module) HandleDM(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate) bool {
	m.mu.Lock()
	sess, ok := m.sessions[msg.Author.ID]
	m.mu.Unlock()
	if !ok {
		return false
	}

	dbSess, err := m.store.GetOnboardingSession(ctx, sess.guildID, msg.Author.ID)
	if err != nil || dbSess == nil || time.Now().After(dbSess.ExpiresAt) {
		// Session expired or gone — clean up silently.
		m.cleanup(ctx, session, sess.guildID, msg.Author.ID, false)
		return true
	}

	switch sess.state {
	case "captcha":
		m.handleCaptchaReply(ctx, session, msg, sess, dbSess)
	case "quiz":
		m.handleQuizReply(ctx, session, msg, sess)
	}
	return true
}

func (m *Module) handleCaptchaReply(
	ctx context.Context,
	session *discordgo.Session,
	msg *discordgo.MessageCreate,
	sess *activeSession,
	dbSess *storage.OnboardingSession,
) {
	input := strings.ToUpper(strings.TrimSpace(msg.Content))
	if input != dbSess.CaptchaCode {
		newAttempts := dbSess.Attempts + 1
		_ = m.store.UpdateOnboardingSession(ctx, sess.guildID, msg.Author.ID, dbSess.Status, newAttempts)

		if newAttempts >= maxAttempts {
			_, _ = session.ChannelMessageSend(msg.ChannelID,
				"❌ Trop de tentatives incorrectes. Tu as été retiré du serveur.")
			m.audit.Log(ctx, audit.LevelWarn, sess.guildID, msg.Author.ID, "onboarding_failed", "max captcha attempts")
			m.cleanup(ctx, session, sess.guildID, msg.Author.ID, true)
			return
		}

		remaining := maxAttempts - newAttempts
		_, _ = session.ChannelMessageSend(msg.ChannelID,
			fmt.Sprintf("❌ Code incorrect. Il te reste **%d** tentative(s).", remaining))
		return
	}

	// Captcha solved — transition to quiz or complete.
	if m.cfg.QuizEnabled && m.cfg.QuizQuestion != "" && m.cfg.QuizAnswer != "" {
		_ = m.store.UpdateOnboardingSession(ctx, sess.guildID, msg.Author.ID, "pending_quiz", dbSess.Attempts)
		m.mu.Lock()
		sess.state = "quiz"
		m.mu.Unlock()
		_, _ = session.ChannelMessageSend(msg.ChannelID, fmt.Sprintf(
			"✅ Captcha validé ! Réponds maintenant à la question suivante :\n\n**%s**",
			m.cfg.QuizQuestion))
		return
	}

	_, _ = session.ChannelMessageSend(msg.ChannelID, "✅ Vérification réussie ! Bienvenue sur le serveur.")
	m.grantRole(session, sess.guildID, msg.Author.ID)
	m.audit.Log(ctx, audit.LevelInfo, sess.guildID, msg.Author.ID, "onboarding_verified", "captcha ok")
	m.cleanup(ctx, nil, sess.guildID, msg.Author.ID, false)
}

func (m *Module) handleQuizReply(
	ctx context.Context,
	session *discordgo.Session,
	msg *discordgo.MessageCreate,
	sess *activeSession,
) {
	answer := strings.TrimSpace(msg.Content)
	if strings.EqualFold(answer, strings.TrimSpace(m.cfg.QuizAnswer)) {
		_, _ = session.ChannelMessageSend(msg.ChannelID, "✅ Bonne réponse ! Bienvenue sur le serveur.")
		m.grantRole(session, sess.guildID, msg.Author.ID)
		m.audit.Log(ctx, audit.LevelInfo, sess.guildID, msg.Author.ID, "onboarding_verified", "quiz ok")
		m.cleanup(ctx, nil, sess.guildID, msg.Author.ID, false)
		return
	}

	_, _ = session.ChannelMessageSend(msg.ChannelID,
		"❌ Mauvaise réponse. Tu as été retiré du serveur.")
	m.audit.Log(ctx, audit.LevelWarn, sess.guildID, msg.Author.ID, "onboarding_failed", "wrong quiz answer")
	m.cleanup(ctx, session, sess.guildID, msg.Author.ID, true)
}

func (m *Module) scheduleExpiry(ctx context.Context, session *discordgo.Session, guildID, userID string, timeout time.Duration) {
	time.Sleep(timeout)

	m.mu.Lock()
	_, still := m.sessions[userID]
	m.mu.Unlock()
	if !still {
		return
	}

	m.audit.Log(ctx, audit.LevelWarn, guildID, userID, "onboarding_timeout", "")
	m.cleanup(ctx, session, guildID, userID, true)
}

func (m *Module) cleanup(ctx context.Context, session *discordgo.Session, guildID, userID string, kick bool) {
	m.mu.Lock()
	delete(m.sessions, userID)
	m.mu.Unlock()

	_ = m.store.DeleteOnboardingSession(ctx, guildID, userID)

	if kick && session != nil {
		_ = session.GuildMemberDelete(guildID, userID)
	}
}

func (m *Module) grantRole(session *discordgo.Session, guildID, userID string) {
	if m.cfg.VerifiedRoleID == "" {
		return
	}
	_ = session.GuildMemberRoleAdd(guildID, userID, m.cfg.VerifiedRoleID)
}

// ── Captcha generation ────────────────────────────────────────────────────────

// generateCode returns a random 6-character code using only unambiguous chars.
func generateCode() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	b := make([]byte, captchaCodeLen)
	for i := range b {
		b[i] = captchaCharset[r.Intn(len(captchaCharset))]
	}
	return string(b)
}

// generateCaptchaPNG renders code as a 200×80 PNG with noise background.
// Uses image/draw (stdlib) for fills and golang.org/x/image/font for text.
func generateCaptchaPNG(code string) ([]byte, error) {
	const (
		width    = 200
		height   = 80
		scale    = 3   // upscale factor for basicfont.Face7x13 (7×13 → 21×39 px)
		charStep = 28  // horizontal spacing between characters
		startX   = 12 // left margin
	)

	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Noisy light-gray background via image/draw + manual variation.
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{R: 230, G: 230, B: 230, A: 255}}, image.Point{}, draw.Src)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			v := uint8(200 + r.Intn(50))
			img.SetRGBA(x, y, color.RGBA{R: v, G: v, B: v, A: 255})
		}
	}

	// Noise dots.
	for i := 0; i < 700; i++ {
		g := uint8(r.Intn(160))
		img.SetRGBA(r.Intn(width), r.Intn(height), color.RGBA{R: g, G: g, B: g, A: 255})
	}

	// Noise lines (Bresenham).
	for i := 0; i < 5; i++ {
		lc := color.RGBA{
			R: uint8(120 + r.Intn(80)),
			G: uint8(120 + r.Intn(80)),
			B: uint8(120 + r.Intn(80)),
			A: 255,
		}
		drawLine(img, r.Intn(width), r.Intn(height), r.Intn(width), r.Intn(height), lc)
	}

	// Render each character at scale× using basicfont.Face7x13.
	face := basicfont.Face7x13
	metrics := face.Metrics()
	charH := (metrics.Ascent + metrics.Descent).Round() // 13 for Face7x13

	baseY := (height - charH*scale) / 2 // vertical centre

	for i, ch := range code {
		cx := startX + i*charStep + r.Intn(5) - 2
		cy := baseY + r.Intn(8) - 4
		fc := color.RGBA{
			R: uint8(r.Intn(80)),
			G: uint8(r.Intn(80)),
			B: uint8(100 + r.Intn(155)),
			A: 255,
		}
		drawGlyphScaled(img, face, ch, cx, cy, scale, fc)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// drawGlyphScaled renders a single glyph onto dst at (baseX, baseY) with
// nearest-neighbour upscaling. It renders the glyph to a temporary RGBA
// image first (black-on-white) then copies set pixels as scale×scale blocks.
func drawGlyphScaled(dst *image.RGBA, face xfont.Face, ch rune, baseX, baseY, scale int, c color.RGBA) {
	metrics := face.Metrics()
	ascent := metrics.Ascent.Round()
	charH := (metrics.Ascent + metrics.Descent).Round()

	adv, ok := face.GlyphAdvance(ch)
	if !ok {
		return
	}
	charW := adv.Round() + 1
	if charW <= 0 || charH <= 0 {
		return
	}

	// Render glyph black-on-white into a small temporary image.
	tmp := image.NewRGBA(image.Rect(0, 0, charW, charH))
	draw.Draw(tmp, tmp.Bounds(), &image.Uniform{color.White}, image.Point{}, draw.Src)

	d := &xfont.Drawer{
		Dst:  tmp,
		Src:  image.NewUniform(color.Black),
		Face: face,
		Dot:  fixed.P(0, ascent),
	}
	d.DrawString(string(ch))

	// Copy scaled pixels to destination.
	dstBounds := dst.Bounds()
	for py := 0; py < charH; py++ {
		for px := 0; px < charW; px++ {
			r, _, _, _ := tmp.At(px, py).RGBA()
			if r < 0x8000 { // dark = text pixel
				for sy := 0; sy < scale; sy++ {
					for sx := 0; sx < scale; sx++ {
						dx := baseX + px*scale + sx
						dy := baseY + py*scale + sy
						if dx >= dstBounds.Min.X && dx < dstBounds.Max.X &&
							dy >= dstBounds.Min.Y && dy < dstBounds.Max.Y {
							dst.SetRGBA(dx, dy, c)
						}
					}
				}
			}
		}
	}
}

// drawLine draws a Bresenham line segment on img with colour c.
func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx := iabs(x1 - x0)
	dy := iabs(y1 - y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	errVal := dx - dy
	bounds := img.Bounds()

	for {
		if x0 >= bounds.Min.X && x0 < bounds.Max.X && y0 >= bounds.Min.Y && y0 < bounds.Max.Y {
			img.SetRGBA(x0, y0, c)
		}
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * errVal
		if e2 > -dy {
			errVal -= dy
			x0 += sx
		}
		if e2 < dx {
			errVal += dx
			y0 += sy
		}
	}
}

func iabs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
