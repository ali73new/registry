// Package ratelimit provides IP-based rate limiting middleware for HTTP servers.
package ratelimit

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Config holds the rate limiting configuration
type Config struct {
	// RequestsPerMinute is the maximum number of requests allowed per minute per IP
	RequestsPerMinute int
	// RequestsPerHour is the maximum number of requests allowed per hour per IP
	RequestsPerHour int
	// CleanupInterval is how often to clean up stale entries (default: 10 minutes)
	CleanupInterval time.Duration
	// SkipPaths are paths that should not be rate limited
	SkipPaths []string
}

// DefaultConfig returns the default rate limiting configuration
func DefaultConfig() Config {
	return Config{
		RequestsPerMinute: 60,
		RequestsPerHour:   1000,
		CleanupInterval:   10 * time.Minute,
		SkipPaths:         []string{"/health", "/ping", "/metrics"},
	}
}

// visitor tracks rate limiting state for a single IP address
type visitor struct {
	minuteLimiter *rate.Limiter
	hourLimiter   *rate.Limiter
	lastSeen      time.Time
}

// RateLimiter implements IP-based rate limiting
type RateLimiter struct {
	config   Config
	visitors map[string]*visitor
	mu       sync.RWMutex
	stopCh   chan struct{}
}

// New creates a new RateLimiter with the given configuration
func New(cfg Config) *RateLimiter {
	rl := &RateLimiter{
		config:   cfg,
		visitors: make(map[string]*visitor),
		stopCh:   make(chan struct{}),
	}

	// Start background cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Stop stops the background cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// cleanupLoop periodically removes stale visitor entries
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCh:
			return
		}
	}
}

// cleanup removes visitors that haven't been seen in the last hour
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	threshold := time.Now().Add(-time.Hour)
	for ip, v := range rl.visitors {
		if v.lastSeen.Before(threshold) {
			delete(rl.visitors, ip)
		}
	}
}

// getVisitor returns the visitor for the given IP, creating one if necessary
func (rl *RateLimiter) getVisitor(ip string) *visitor {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		// Create rate limiters:
		// - Minute limiter: allows RequestsPerMinute requests per minute with burst of same
		// - Hour limiter: allows RequestsPerHour requests per hour with burst of same
		minuteRate := rate.Limit(float64(rl.config.RequestsPerMinute) / 60.0) // requests per second
		hourRate := rate.Limit(float64(rl.config.RequestsPerHour) / 3600.0)   // requests per second

		v = &visitor{
			minuteLimiter: rate.NewLimiter(minuteRate, rl.config.RequestsPerMinute),
			hourLimiter:   rate.NewLimiter(hourRate, rl.config.RequestsPerHour),
			lastSeen:      time.Now(),
		}
		rl.visitors[ip] = v
	} else {
		v.lastSeen = time.Now()
	}

	return v
}

// Allow checks if a request from the given IP should be allowed
func (rl *RateLimiter) Allow(ip string) bool {
	v := rl.getVisitor(ip)

	// Both limiters must allow the request
	if !v.minuteLimiter.Allow() {
		return false
	}
	if !v.hourLimiter.Allow() {
		return false
	}
	return true
}

// shouldSkip returns true if the path should not be rate limited
func (rl *RateLimiter) shouldSkip(path string) bool {
	for _, skipPath := range rl.config.SkipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath+"/") {
			return true
		}
	}
	return false
}

// getClientIP extracts the client IP from the request
// It considers X-Forwarded-For and X-Real-IP headers for reverse proxy scenarios
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (can contain multiple IPs)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		if idx := strings.Index(xff, ","); idx != -1 {
			xff = xff[:idx]
		}
		xff = strings.TrimSpace(xff)
		if xff != "" {
			return xff
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr might not have a port
		return r.RemoteAddr
	}
	return ip
}

// Middleware returns an HTTP middleware that enforces rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for certain paths
		if rl.shouldSkip(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := getClientIP(r)

		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)

			errorBody := map[string]interface{}{
				"title":  "Too Many Requests",
				"status": http.StatusTooManyRequests,
				"detail": "Rate limit exceeded. Please reduce request frequency and retry after some time.",
			}

			jsonData, err := json.Marshal(errorBody)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(jsonData)
			return
		}

		next.ServeHTTP(w, r)
	})
}
