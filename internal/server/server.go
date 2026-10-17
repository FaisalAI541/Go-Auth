package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/authservice/auth-service/internal/domain"
	"github.com/authservice/auth-service/internal/handler"
	"github.com/authservice/auth-service/internal/middleware"
)

// Config holds server configuration.
type Config struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// Server wraps the HTTP server with dependencies.
type Server struct {
	httpServer      *http.Server
	logger          *slog.Logger
	shutdownTimeout time.Duration
}

// New creates a new Server with all routes and middleware configured.
func New(
	cfg Config,
	logger *slog.Logger,
	authHandler *handler.AuthHandler,
	healthHandler *handler.HealthHandler,
	tokenSvc domain.TokenService,
	rateLimiter *middleware.RateLimiter,
) *Server {
	r := chi.NewRouter()

	// Global middleware stack
	r.Use(middleware.Recovery(logger))
	r.Use(middleware.RequestLogger(logger))
	r.Use(middleware.CORS(middleware.DefaultCORSConfig()))
	r.Use(rateLimiter.Handler())

	// Health check routes (no auth required)
	r.Route("/health", func(r chi.Router) {
		r.Get("/live", healthHandler.Liveness)
		r.Get("/ready", healthHandler.Readiness)
	})

	// API v1 routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public routes
		r.Group(func(r chi.Router) {
			r.Post("/auth/register", authHandler.Register)
			r.Post("/auth/login", authHandler.Login)
			r.Post("/auth/refresh", authHandler.Refresh)
		})

		// Protected routes (require valid JWT)
		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(tokenSvc))
			r.Post("/auth/logout", authHandler.Logout)
			r.Get("/auth/me", authHandler.Me)
		})
	})

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      r,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return &Server{
		httpServer:      httpServer,
		logger:          logger,
		shutdownTimeout: cfg.ShutdownTimeout,
	}
}

// Start begins listening and serving. It blocks until the server stops.
func (s *Server) Start() error {
	s.logger.Info("server starting", slog.String("addr", s.httpServer.Addr))
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() error {
	s.logger.Info("server shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}
