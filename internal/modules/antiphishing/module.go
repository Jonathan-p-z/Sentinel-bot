package antiphishing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"sentinel-adaptive/internal/modules/audit"
	"sentinel-adaptive/internal/risk"
	"sentinel-adaptive/internal/utils"

	"github.com/bwmarrin/discordgo"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"golang.org/x/net/publicsuffix"
)

var keywordSignals = []string{"nitro", "free", "claim", "gift", "steam", "giveaway"}

// dateLayouts lists the formats used by whois-parser for CreatedDate.
var dateLayouts = []string{
	"2006-01-02T15:04:05Z",
	time.RFC3339,
	"2006-01-02 15:04:05 +0000 UTC",
	"2006-01-02 15:04:05 UTC",
	"2006-01-02",
}

// whoisCacheEntry stores the cached domain age score with a TTL.
type whoisCacheEntry struct {
	score     float64
	expiresAt time.Time
}

// reputationResult holds the aggregated output of the reputation pipeline.
type reputationResult struct {
	score        float64
	safeBrowsing bool // true when Google Safe Browsing matched → CRIT level
}

type Module struct {
	risk  *risk.Engine
	audit *audit.Logger

	whoisCacheMu sync.Mutex
	whoisCache   map[string]whoisCacheEntry
}

func New(riskEngine *risk.Engine, auditLogger *audit.Logger) *Module {
	return &Module{
		risk:       riskEngine,
		audit:      auditLogger,
		whoisCache: make(map[string]whoisCacheEntry),
	}
}

func (m *Module) HandleMessage(ctx context.Context, session *discordgo.Session, msg *discordgo.MessageCreate, guildID string, allowlist, blocklist map[string]struct{}, phishingRisk int, auditOnly bool) (float64, bool, string) {
	urls := utils.ExtractURLs(msg.Content)
	if len(urls) == 0 {
		return 0, false, ""
	}

	// Phase 1: static blocklist check — fast path, no network I/O.
	for _, raw := range urls {
		normalized, domain, err := utils.NormalizeURL(raw)
		if err != nil {
			continue
		}
		allowed, blocked := utils.DomainMatch(domain, allowlist, blocklist)
		if allowed {
			continue
		}
		if blocked || hasKeywords(msg.Content) {
			detail := "suspicious link: " + normalized
			m.audit.Log(ctx, audit.LevelWarn, guildID, msg.Author.ID, "anti_phishing", detail)
			score := m.risk.AddRisk(guildID, msg.Author.ID, float64(phishingRisk))
			if !auditOnly {
				_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
			}
			return score, true, detail
		}
	}

	// Phase 2: reputation pipeline for URLs that passed the static check.
	for _, raw := range urls {
		_, domain, err := utils.NormalizeURL(raw)
		if err != nil {
			continue
		}
		allowed, _ := utils.DomainMatch(domain, allowlist, blocklist)
		if allowed {
			continue
		}

		rep := m.runReputationPipeline(ctx, raw, domain)
		if rep.score <= 0 {
			continue
		}

		level := audit.LevelWarn
		if rep.safeBrowsing {
			level = audit.LevelCrit
		}
		detail := fmt.Sprintf("reputation: domain=%s score=%.0f", domain, rep.score)
		m.audit.Log(ctx, level, guildID, msg.Author.ID, "anti_phishing", detail)
		score := m.risk.AddRisk(guildID, msg.Author.ID, rep.score)
		if !auditOnly {
			_ = session.ChannelMessageDelete(msg.ChannelID, msg.ID)
		}
		return score, true, detail
	}

	return 0, false, ""
}

// runReputationPipeline runs all three reputation checks concurrently under a
// 5-second global timeout. It always fails open: errors return score 0.
//
// Goroutine A — steps 1+2: resolve redirects then check WHOIS domain age.
// Goroutine B — step 3:    Google Safe Browsing lookup (skipped when key absent).
func (m *Module) runReputationPipeline(ctx context.Context, rawURL, origDomain string) reputationResult {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	type partial struct {
		score        float64
		safeBrowsing bool
	}
	ch := make(chan partial, 2)

	// Goroutine A: step 1 (redirect resolution) → step 2 (WHOIS age).
	go func() {
		finalDomain := resolveRedirects(ctx, rawURL)
		if finalDomain == "" {
			finalDomain = origDomain
		}
		ch <- partial{score: m.checkWhoisAge(ctx, finalDomain)}
	}()

	// Goroutine B: step 3 (Safe Browsing).
	go func() {
		score := m.checkSafeBrowsing(ctx, rawURL)
		ch <- partial{score: score, safeBrowsing: score > 0}
	}()

	var out reputationResult
	for i := 0; i < 2; i++ {
		select {
		case p := <-ch:
			out.score += p.score
			if p.safeBrowsing {
				out.safeBrowsing = true
			}
		case <-ctx.Done():
			return out
		}
	}
	return out
}

// resolveRedirects follows HTTP redirects (max 5 hops, 3s timeout) and returns
// the hostname of the final URL. Returns "" on any error (fail open).
func resolveRedirects(ctx context.Context, rawURL string) string {
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Timeout: 3 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sentinel-bot/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	_ = resp.Body.Close()
	return resp.Request.URL.Hostname()
}

// checkWhoisAge queries WHOIS for the registrable domain and returns a risk
// score based on domain age. Results are cached for 1 hour.
// Returns 0 on any error (fail open).
//
//	< 7 days  → +70
//	< 30 days → +40
func (m *Module) checkWhoisAge(ctx context.Context, domain string) float64 {
	registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil || registrable == "" {
		registrable = domain
	}

	// Cache lookup.
	m.whoisCacheMu.Lock()
	if entry, ok := m.whoisCache[registrable]; ok && time.Now().Before(entry.expiresAt) {
		m.whoisCacheMu.Unlock()
		return entry.score
	}
	m.whoisCacheMu.Unlock()

	// Wrap the blocking WHOIS call so the context timeout is respected.
	type whoisResp struct {
		data string
		err  error
	}
	respCh := make(chan whoisResp, 1)
	go func() {
		data, err := whois.Whois(registrable)
		respCh <- whoisResp{data, err}
	}()

	whoisCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var raw string
	select {
	case r := <-respCh:
		if r.err != nil {
			return 0
		}
		raw = r.data
	case <-whoisCtx.Done():
		return 0
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil || parsed.Domain == nil || parsed.Domain.CreatedDate == "" {
		return 0
	}

	createdAt, ok := parseDomainDate(parsed.Domain.CreatedDate)
	if !ok {
		return 0
	}

	age := time.Since(createdAt)
	var score float64
	switch {
	case age < 7*24*time.Hour:
		score = 70
	case age < 30*24*time.Hour:
		score = 40
	}

	// Populate cache (even for score=0 so established domains don't keep being queried).
	m.whoisCacheMu.Lock()
	m.whoisCache[registrable] = whoisCacheEntry{score: score, expiresAt: time.Now().Add(time.Hour)}
	m.whoisCacheMu.Unlock()

	return score
}

// checkSafeBrowsing queries the Google Safe Browsing v4 API.
// Returns 0 immediately when SAFE_BROWSING_API_KEY is unset or on any error.
func (m *Module) checkSafeBrowsing(ctx context.Context, rawURL string) float64 {
	apiKey := os.Getenv("SAFE_BROWSING_API_KEY")
	if apiKey == "" {
		return 0
	}

	body, err := json.Marshal(map[string]any{
		"client": map[string]string{
			"clientId":      "sentinel-bot",
			"clientVersion": "1.0",
		},
		"threatInfo": map[string]any{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []map[string]string{{"url": rawURL}},
		},
	})
	if err != nil {
		return 0
	}

	endpoint := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + apiKey
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return 0
	}
	defer resp.Body.Close()

	var result struct {
		Matches []json.RawMessage `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0
	}
	if len(result.Matches) > 0 {
		return 80
	}
	return 0
}

func hasKeywords(content string) bool {
	lower := strings.ToLower(content)
	for _, keyword := range keywordSignals {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func parseDomainDate(s string) (time.Time, bool) {
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
