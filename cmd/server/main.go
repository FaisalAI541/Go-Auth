package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/authservice/auth-service/internal/config"
	"github.com/authservice/auth-service/internal/handler"
	"github.com/authservice/auth-service/internal/middleware"
	"github.com/authservice/auth-service/internal/repository"
	"github.com/authservice/auth-service/internal/server"
	"github.com/authservice/auth-service/internal/service"
	"github.com/authservice/auth-service/pkg/hash"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Initialize structured logger
	var logLevel slog.Level
	switch cfg.Log.Level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	var logHandler slog.Handler
	if cfg.Log.Format == "text" {
		logHandler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		logHandler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}
	logger := slog.New(logHandler)
	slog.SetDefault(logger)

	// Connect to database
	ctx := context.Background()
	pool, err := repository.NewPostgresPool(ctx, repository.PostgresConfig{
		DSN:             cfg.Database.DSN,
		MaxConns:        cfg.Database.MaxConns,
		MinConns:        cfg.Database.MinConns,
		MaxConnLifetime: cfg.Database.MaxConnLifetime,
		MaxConnIdleTime: cfg.Database.MaxConnIdleTime,
	})
	if err != nil {
		logger.Error("failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer pool.Close()
	logger.Info("database connection established")

	// Initialize repositories
	userRepo := repository.NewUserRepository(pool)
	tokenRepo := repository.NewTokenRepository(pool)

	// Initialize services
	hasher := hash.NewHasher(12)
	tokenSvc := service.NewJWTTokenService(service.TokenConfig{
		AccessSecret:  cfg.JWT.AccessSecret,
		RefreshSecret: cfg.JWT.RefreshSecret,
		AccessExpiry:  cfg.JWT.AccessExpiry,
		RefreshExpiry: cfg.JWT.RefreshExpiry,
		Issuer:        cfg.JWT.Issuer,
	})
	authSvc := service.NewAuthService(userRepo, tokenRepo, tokenSvc, hasher, logger, cfg.JWT.RefreshExpiry)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authSvc, logger)
	healthHandler := handler.NewHealthHandler(pool)

	// Initialize rate limiter
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst, logger)

	// Create and start server
	srv := server.New(
		server.Config{
			Addr:            cfg.Server.Host,
			ReadTimeout:     cfg.Server.ReadTimeout,
			WriteTimeout:    cfg.Server.WriteTimeout,
			IdleTimeout:     cfg.Server.IdleTimeout,
			ShutdownTimeout: cfg.Server.ShutdownTimeout,
		},
		logger,
		authHandler,
		healthHandler,
		tokenSvc,
		rateLimiter,
	)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	logger.Info("server started", slog.String("addr", cfg.Server.Host))

	<-quit
	logger.Info("shutdown signal received")

	if err := srv.Shutdown(); err != nil {
		logger.Error("server shutdown error", slog.String("error", err.Error()))
		os.Exit(1)
	}

	logger.Info("server stopped gracefully")
}
