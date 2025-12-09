package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/rs/cors"

	v0 "github.com/modelcontextprotocol/registry/internal/api/handlers/v0"
	"github.com/modelcontextprotocol/registry/internal/api/ratelimit"
	"github.com/modelcontextprotocol/registry/internal/api/router"
	"github.com/modelcontextprotocol/registry/internal/config"
	"github.com/modelcontextprotocol/registry/internal/service"
	"github.com/modelcontextprotocol/registry/internal/telemetry"
)

// TrailingSlashMiddleware redirects requests with trailing slashes to their canonical form
func TrailingSlashMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only redirect if the path is not "/" and ends with a "/"
		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			// Create a copy of the URL and remove the trailing slash
			newURL := *r.URL
			newURL.Path = strings.TrimSuffix(r.URL.Path, "/")

			// Use 308 Permanent Redirect to preserve the request method
			http.Redirect(w, r, newURL.String(), http.StatusPermanentRedirect)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Server represents the HTTP server
type Server struct {
	config      *config.Config
	registry    service.RegistryService
	humaAPI     huma.API
	server      *http.Server
	rateLimiter *ratelimit.RateLimiter
}

// NewServer creates a new HTTP server
func NewServer(cfg *config.Config, registryService service.RegistryService, metrics *telemetry.Metrics, versionInfo *v0.VersionBody) *Server {
	// Create HTTP mux and Huma API
	mux := http.NewServeMux()

	api := router.NewHumaAPI(cfg, registryService, mux, metrics, versionInfo)

	// Configure CORS with permissive settings for public API
	corsHandler := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Content-Type", "Content-Length"},
		AllowCredentials: false, // Must be false when AllowedOrigins is "*"
		MaxAge:           86400, // 24 hours
	})

	// Wrap the mux with middleware stack
	// Order: TrailingSlash -> RateLimit -> CORS -> Mux
	handler := corsHandler.Handler(mux)

	// Initialize rate limiter if enabled
	var rateLimiter *ratelimit.RateLimiter
	if cfg.RateLimitEnabled {
		rateLimitConfig := ratelimit.Config{
			RequestsPerMinute: cfg.RateLimitRequestsPerMinute,
			RequestsPerHour:   cfg.RateLimitRequestsPerHour,
			CleanupInterval:   10 * time.Minute,
			SkipPaths:         []string{"/health", "/ping", "/metrics"},
		}
		rateLimiter = ratelimit.New(rateLimitConfig)
		handler = rateLimiter.Middleware(handler)
		log.Printf("Rate limiting enabled: %d req/min, %d req/hour per IP",
			cfg.RateLimitRequestsPerMinute, cfg.RateLimitRequestsPerHour)
	}

	handler = TrailingSlashMiddleware(handler)

	server := &Server{
		config:      cfg,
		registry:    registryService,
		humaAPI:     api,
		rateLimiter: rateLimiter,
		server: &http.Server{
			Addr:              cfg.ServerAddress,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}

	return server
}

// Start begins listening for incoming HTTP requests
func (s *Server) Start() error {
	log.Printf("HTTP server starting on %s", s.config.ServerAddress)
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	// Stop rate limiter cleanup goroutine
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	return s.server.Shutdown(ctx)
}
