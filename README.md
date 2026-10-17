# High-Concurrency Auth Service in Go

A production-grade, high-concurrency authentication and authorization microservice written in Go using clean hexagonal/modular architecture.

## Architecture & Design

```
auth-service/
├── cmd/
│   └── server/
│       └── main.go                 # App entrypoint, dependency injection & graceful shutdown
├── internal/
│   ├── config/
│   │   └── config.go               # Strongly-typed config loaded from environment variables
│   ├── domain/                     # Core business entities & repository/service interfaces
│   │   ├── user.go                 # User model, DTOs, and UserRepository interface
│   │   ├── token.go                # RefreshToken model, claims, and TokenService interface
│   │   └── errors.go               # Domain sentinel errors
│   ├── repository/                 # Persistence layer (PostgreSQL with pgxpool)
│   │   ├── postgres.go             # High-concurrency connection pool setup
│   │   ├── user_repo.go            # User persistence implementation
│   │   └── token_repo.go           # Refresh token storage and revocation
│   ├── service/                    # Business logic
│   │   ├── auth_service.go         # Register, Login, Refresh, Logout, Profile orchestration
│   │   └── token_service.go        # Dual JWT token management (Access + Refresh tokens)
│   ├── handler/                    # HTTP presentation layer
│   │   ├── auth.go                 # Auth API endpoints (REST)
│   │   ├── health.go               # Kubernetes liveness & readiness probes
│   │   └── response.go             # Standardized JSON response helpers
│   ├── middleware/                 # Production HTTP middleware pipeline
│   │   ├── auth.go                 # JWT validation & context injection
│   │   ├── ratelimit.go            # Per-IP token-bucket rate limiting with background cleanup
│   │   ├── logging.go              # Structured logging (log/slog) with duration & status
│   │   ├── recovery.go             # Panic recovery with stack-trace logging
│   │   └── cors.go                 # Configurable CORS handling
│   └── server/
│       └── server.go               # Chi router setup, route grouping & HTTP timeouts
├── pkg/
│   └── hash/
│       └── bcrypt.go               # Password hashing (bcrypt) & token hashing (SHA-256)
├── migrations/
│   └── 001_initial_schema.sql      # PostgreSQL schema with UUIDs & indexes
├── .env.example                    # Environment variable template
├── Dockerfile                      # Multi-stage scratch/alpine minimal container
├── docker-compose.yml              # Local testing environment with PostgreSQL 16
└── go.mod                          # Dependencies definition
```

## Concurrency & Performance Highlights

1. **pgx/v5 Connection Pool (`pgxpool`)**:
   - Connection pooling with configurable `MaxConns`, `MinConns`, `MaxConnLifetime`, and `MaxConnIdleTime`.
   - Native binary format protocol support for PostgreSQL.
2. **Stateless Access Tokens + Opaque Refresh Token Rotation**:
   - Access tokens (JWT HS256) expire in 15 minutes, avoiding DB lookups for protected endpoints.
   - Refresh tokens are hashed via SHA-256 before storage in PostgreSQL; tokens are rotated on each refresh.
3. **Concurrent-Safe In-Memory Per-IP Rate Limiting**:
   - Token bucket algorithm using `golang.org/x/time/rate`.
   - Reader-writer mutex (`sync.RWMutex`) and a background ticker goroutine that reaps inactive visitors to prevent memory leaks.
4. **Resilient HTTP Server**:
   - Explicit `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and context-driven graceful shutdown with signal trapping (`SIGINT`, `SIGTERM`).
5. **Zero Allocations & Low Overhead**:
   - Uses `go-chi/chi/v5` for lightweight routing.
   - Structured logging via Go 1.21+ native `log/slog`.

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/health/live` | None | Liveness probe (checks server status) |
| `GET` | `/health/ready` | None | Readiness probe (verifies database ping) |
| `POST` | `/api/v1/auth/register` | None | Register new user account |
| `POST` | `/api/v1/auth/login` | None | Login with email and password |
| `POST` | `/api/v1/auth/refresh` | None | Refresh access token using refresh token |
| `POST` | `/api/v1/auth/logout` | Bearer | Revoke user's refresh tokens |
| `GET` | `/api/v1/auth/me` | Bearer | Retrieve authenticated user profile |

## Quick Start with Docker Compose

Run the entire service and PostgreSQL database with one command:

```bash
docker compose up --build
```

The database migrations in `migrations/001_initial_schema.sql` are automatically executed on startup.

## Local Configuration (`.env`)

Copy `.env.example` to `.env`:

```env
SERVER_HOST=:8080
DATABASE_DSN=postgres://authuser:authpass@localhost:5432/authdb?sslmode=disable
DATABASE_MAX_CONNS=25
DATABASE_MIN_CONNS=5
JWT_ACCESS_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key
RATE_LIMIT_RPS=100
RATE_LIMIT_BURST=200
LOG_LEVEL=info
LOG_FORMAT=json
```
