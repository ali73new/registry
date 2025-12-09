package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/registry/internal/api/ratelimit"
)

const (
	testLocalAddr    = "127.0.0.1:12345"
	testLocalAltAddr = "127.0.0.1:12346"
)

func TestRateLimiter_Allow(t *testing.T) {
	cfg := ratelimit.Config{
		RequestsPerMinute: 5,
		RequestsPerHour:   10,
		CleanupInterval:   time.Hour, // Long interval to avoid cleanup during test
		SkipPaths:         []string{"/health"},
	}
	rl := ratelimit.New(cfg)
	defer rl.Stop()

	ip := "192.168.1.1"

	// Should allow the first 5 requests (minute limit)
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be blocked (minute limit exceeded)
	if rl.Allow(ip) {
		t.Error("Request 6 should be blocked due to minute limit")
	}

	// Different IP should still be allowed
	if !rl.Allow("192.168.1.2") {
		t.Error("Request from different IP should be allowed")
	}
}

func TestRateLimiter_HourlyLimit(t *testing.T) {
	// Configure with high minute limit but low hour limit
	cfg := ratelimit.Config{
		RequestsPerMinute: 100,
		RequestsPerHour:   5,
		CleanupInterval:   time.Hour,
		SkipPaths:         []string{"/health"},
	}
	rl := ratelimit.New(cfg)
	defer rl.Stop()

	ip := "192.168.1.1"

	// Should allow up to hour limit
	for i := 0; i < 5; i++ {
		if !rl.Allow(ip) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Next request should be blocked by hour limit
	if rl.Allow(ip) {
		t.Error("Request should be blocked due to hour limit")
	}
}

func TestRateLimiter_Middleware(t *testing.T) {
	cfg := ratelimit.Config{
		RequestsPerMinute: 2,
		RequestsPerHour:   100,
		CleanupInterval:   time.Hour,
		SkipPaths:         []string{"/health", "/ping"},
	}
	rl := ratelimit.New(cfg)
	defer rl.Stop()

	// Create a simple handler that returns OK
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	middleware := rl.Middleware(handler)

	t.Run("allows requests within limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v0/servers", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("blocks requests over limit", func(t *testing.T) {
		// Exhaust the limit for this IP
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest(http.MethodGet, "/v0/servers", nil)
			req.RemoteAddr = "10.0.0.2:12345"
			w := httptest.NewRecorder()
			middleware.ServeHTTP(w, req)
		}

		// This request should be blocked
		req := httptest.NewRequest(http.MethodGet, "/v0/servers", nil)
		req.RemoteAddr = "10.0.0.2:12345"
		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, w.Code)
		}

		// Check Retry-After header
		if w.Header().Get("Retry-After") != "60" {
			t.Errorf("expected Retry-After header to be 60, got %s", w.Header().Get("Retry-After"))
		}

		// Check Content-Type
		if w.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("expected Content-Type application/problem+json, got %s", w.Header().Get("Content-Type"))
		}
	})

	t.Run("skips health endpoint", func(t *testing.T) {
		// Use an IP that's already rate limited
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			req.RemoteAddr = "10.0.0.3:12345"
			w := httptest.NewRecorder()
			middleware.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("health endpoint should always be allowed, got status %d on request %d", w.Code, i+1)
			}
		}
	})

	t.Run("skips ping endpoint", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/ping", nil)
			req.RemoteAddr = "10.0.0.4:12345"
			w := httptest.NewRecorder()
			middleware.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("ping endpoint should always be allowed, got status %d on request %d", w.Code, i+1)
			}
		}
	})
}

func TestGetClientIP(t *testing.T) {
	cfg := ratelimit.Config{
		RequestsPerMinute: 1,
		RequestsPerHour:   100,
		CleanupInterval:   time.Hour,
		SkipPaths:         []string{},
	}
	rl := ratelimit.New(cfg)
	defer rl.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := rl.Middleware(handler)

	t.Run("uses X-Forwarded-For header", func(t *testing.T) {
		// First request from this forwarded IP
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = testLocalAddr
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("first request should be allowed, got status %d", w.Code)
		}

		// Second request should be blocked (same forwarded IP)
		req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = testLocalAltAddr
		req2.Header.Set("X-Forwarded-For", "203.0.113.1")
		w2 := httptest.NewRecorder()
		middleware.ServeHTTP(w2, req2)

		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("second request should be blocked, got status %d", w2.Code)
		}
	})

	t.Run("uses first IP from X-Forwarded-For with multiple IPs", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = testLocalAddr
		req.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.1, 192.168.1.1")
		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("first request should be allowed, got status %d", w.Code)
		}

		// Second request with same first IP should be blocked
		req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = testLocalAltAddr
		req2.Header.Set("X-Forwarded-For", "203.0.113.2, 10.0.0.2")
		w2 := httptest.NewRecorder()
		middleware.ServeHTTP(w2, req2)

		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("second request should be blocked, got status %d", w2.Code)
		}
	})

	t.Run("uses X-Real-IP header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = testLocalAddr
		req.Header.Set("X-Real-IP", "203.0.113.3")
		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("first request should be allowed, got status %d", w.Code)
		}

		// Second request should be blocked
		req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = testLocalAltAddr
		req2.Header.Set("X-Real-IP", "203.0.113.3")
		w2 := httptest.NewRecorder()
		middleware.ServeHTTP(w2, req2)

		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("second request should be blocked, got status %d", w2.Code)
		}
	})

	t.Run("falls back to RemoteAddr", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "203.0.113.4:12345"
		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("first request should be allowed, got status %d", w.Code)
		}

		// Second request from same IP should be blocked
		req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = "203.0.113.4:12346"
		w2 := httptest.NewRecorder()
		middleware.ServeHTTP(w2, req2)

		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("second request should be blocked, got status %d", w2.Code)
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := ratelimit.DefaultConfig()

	if cfg.RequestsPerMinute != 60 {
		t.Errorf("expected RequestsPerMinute to be 60, got %d", cfg.RequestsPerMinute)
	}

	if cfg.RequestsPerHour != 1000 {
		t.Errorf("expected RequestsPerHour to be 1000, got %d", cfg.RequestsPerHour)
	}

	if cfg.CleanupInterval != 10*time.Minute {
		t.Errorf("expected CleanupInterval to be 10 minutes, got %v", cfg.CleanupInterval)
	}

	// Check skip paths
	expectedSkipPaths := map[string]bool{
		"/health":  true,
		"/ping":    true,
		"/metrics": true,
	}

	for _, path := range cfg.SkipPaths {
		if !expectedSkipPaths[path] {
			t.Errorf("unexpected skip path: %s", path)
		}
		delete(expectedSkipPaths, path)
	}

	if len(expectedSkipPaths) > 0 {
		t.Errorf("missing skip paths: %v", expectedSkipPaths)
	}
}
