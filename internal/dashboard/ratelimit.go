package dashboard

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type rateLimiter struct {
	mu      sync.Mutex
	clients map[string]*rlClient
}

type rlClient struct {
	count    int
	windowAt time.Time
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{clients: make(map[string]*rlClient)}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) Allow(ip string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	c := rl.clients[ip]
	if c == nil || now.Sub(c.windowAt) > window {
		rl.clients[ip] = &rlClient{count: 1, windowAt: now}
		return true
	}
	c.count++
	return c.count <= limit
}

// cleanup purges stale entries every 5 minutes to avoid unbounded memory growth.
func (rl *rateLimiter) cleanup() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, c := range rl.clients {
			if c.windowAt.Before(cutoff) {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the real client IP, respecting Cloudflare and standard proxy headers.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// limitAuth is a middleware that rate-limits auth endpoints:
// max 20 attempts per IP per 10 minutes.
func (s *Server) limitAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !s.rl.Allow(ip, 20, 10*time.Minute) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}
