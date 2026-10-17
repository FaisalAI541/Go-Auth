package handler

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	pool *pgxpool.Pool
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler(pool *pgxpool.Pool) *HealthHandler {
	return &HealthHandler{pool: pool}
}

// Liveness returns 200 OK if the service is running.
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

// Readiness checks database connectivity.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	if err := h.pool.Ping(r.Context()); err != nil {
		respondError(w, http.StatusServiceUnavailable, "database not available")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
