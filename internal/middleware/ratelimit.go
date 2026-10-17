package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// visitor tracks rate limit state per IP.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter implements per-IP rate limiting with automatic cleanup.
type RateLimiter struct {
	mu       sync.RWMutex
	visitors map[string]*visitor
	rate     rate.Limit
	burst    int
	logger   *slog.Logger
}

// NewRateLimiter creates a new RateLimiter and starts background cleanup.
func NewRateLimiter(rps float64, burst int, logger *slog.Logger) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate.Limit(rps),
		burst:    burst,
		logger:   logger,
	}

	// Background goroutine to clean up stale entries every minute.
	go rl.cleanupVisitors()

	return rl
}

func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.RLock()
	v, exists := rl.visitors[ip]
	rl.mu.RUnlock()

	if exists {
		rl.mu.Lock()
		v.lastSeen = time.Now()
		rl.mu.Unlock()
		return v.limiter
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock.
	if v, exists := rl.visitors[ip]; exists {
		v.lastSeen = time.Now()
		return v.limiter
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.visitors[ip] = &visitor{limiter: limiter, lastSeen: time.Now()}
	return limiter
}

func (rl *RateLimiter) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Handler returns HTTP middleware that enforces rate limits.
func (rl *RateLimiter) Handler() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			limiter := rl.getVisitor(ip)
			if !limiter.Allow() {
				rl.logger.Warn("rate limit exceeded",
					slog.String("ip", ip),
					slog.String("path", r.URL.Path),
				)
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
