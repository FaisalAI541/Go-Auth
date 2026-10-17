package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the auth service.
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	JWT       JWTConfig
	RateLimit RateLimitConfig
	Log       LogConfig
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	Host            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// DatabaseConfig holds database connection configuration.
type DatabaseConfig struct {
	DSN             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// JWTConfig holds JWT token configuration.
type JWTConfig struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	Issuer        string
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level  string
	Format string
}

// Load reads configuration from environment variables, applies defaults,
// and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:            envString("SERVER_HOST", ":8080"),
			ReadTimeout:     envDuration("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout:    envDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:     envDuration("SERVER_IDLE_TIMEOUT", 120*time.Second),
			ShutdownTimeout: envDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
		},
		Database: DatabaseConfig{
			DSN:             envString("DATABASE_DSN", ""),
			MaxConns:        envInt32("DATABASE_MAX_CONNS", 25),
			MinConns:        envInt32("DATABASE_MIN_CONNS", 5),
			MaxConnLifetime: envDuration("DATABASE_MAX_CONN_LIFETIME", time.Hour),
			MaxConnIdleTime: envDuration("DATABASE_MAX_CONN_IDLE_TIME", 30*time.Minute),
		},
		JWT: JWTConfig{
			AccessSecret:  envString("JWT_ACCESS_SECRET", ""),
			RefreshSecret: envString("JWT_REFRESH_SECRET", ""),
			AccessExpiry:  envDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshExpiry: envDuration("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
			Issuer:        envString("JWT_ISSUER", "auth-service"),
		},
		RateLimit: RateLimitConfig{
			RequestsPerSecond: envFloat64("RATE_LIMIT_RPS", 100),
			Burst:             envInt("RATE_LIMIT_BURST", 200),
		},
		Log: LogConfig{
			Level:  envString("LOG_LEVEL", "info"),
			Format: envString("LOG_FORMAT", "json"),
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// Validate checks that all required configuration fields are set and returns
// a meaningful error describing any missing or invalid fields.
func (c *Config) Validate() error {
	var errs []error

	if c.Database.DSN == "" {
		errs = append(errs, errors.New("DATABASE_DSN is required"))
	}
	if c.JWT.AccessSecret == "" {
		errs = append(errs, errors.New("JWT_ACCESS_SECRET is required"))
	}
	if c.JWT.RefreshSecret == "" {
		errs = append(errs, errors.New("JWT_REFRESH_SECRET is required"))
	}

	if len(errs) > 0 {
		return fmt.Errorf("missing required configuration: %w", errors.Join(errs...))
	}

	return nil
}

// envString returns the value of the environment variable named by key,
// or defaultVal if the variable is not set.
func envString(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// envInt returns the value of the environment variable named by key parsed
// as an int, or defaultVal if the variable is not set or cannot be parsed.
func envInt(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return i
}

// envInt32 returns the value of the environment variable named by key parsed
// as an int32, or defaultVal if the variable is not set or cannot be parsed.
func envInt32(key string, defaultVal int32) int32 {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	i, err := strconv.ParseInt(v, 10, 32)
	if err != nil {
		return defaultVal
	}
	return int32(i)
}

// envFloat64 returns the value of the environment variable named by key parsed
// as a float64, or defaultVal if the variable is not set or cannot be parsed.
func envFloat64(key string, defaultVal float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return defaultVal
	}
	return f
}

// envDuration returns the value of the environment variable named by key parsed
// as a time.Duration, or defaultVal if the variable is not set or cannot be parsed.
func envDuration(key string, defaultVal time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return defaultVal
	}
	return d
}
