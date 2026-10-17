package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/authservice/auth-service/internal/domain"
	"github.com/authservice/auth-service/internal/middleware"
	"github.com/authservice/auth-service/internal/service"
)

// AuthHandler handles authentication HTTP endpoints.
type AuthHandler struct {
	authSvc *service.AuthService
	logger  *slog.Logger
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authSvc *service.AuthService, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, logger: logger}
}

// Register handles user registration.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer r.Body.Close()

	resp, err := h.authSvc.Register(r.Context(), &req)
	if err != nil {
		h.handleError(w, err)
		return
	}

	respondJSON(w, http.StatusCreated, resp)
}

// Login handles user authentication.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer r.Body.Close()

	resp, err := h.authSvc.Login(r.Context(), &req)
	if err != nil {
		h.handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Refresh handles token refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req domain.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer r.Body.Close()

	resp, err := h.authSvc.RefreshTokens(r.Context(), &req)
	if err != nil {
		h.handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, resp)
}

// Logout handles user logout (revokes all refresh tokens).
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.authSvc.Logout(r.Context(), userID); err != nil {
		h.handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"message": "successfully logged out"})
}

// Me returns the current authenticated user's profile.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.authSvc.GetUser(r.Context(), userID)
	if err != nil {
		h.handleError(w, err)
		return
	}

	respondJSON(w, http.StatusOK, user)
}

// handleError maps domain errors to HTTP status codes.
func (h *AuthHandler) handleError(w http.ResponseWriter, err error) {
	h.logger.Error("request error", slog.String("error", err.Error()))

	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		respondError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, domain.ErrInvalidCredentials):
		respondError(w, http.StatusUnauthorized, "invalid email or password")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		respondError(w, http.StatusConflict, "user already exists")
	case errors.Is(err, domain.ErrUserNotFound):
		respondError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, domain.ErrTokenExpired):
		respondError(w, http.StatusUnauthorized, "token expired")
	case errors.Is(err, domain.ErrTokenInvalid):
		respondError(w, http.StatusUnauthorized, "token invalid")
	case errors.Is(err, domain.ErrTokenRevoked):
		respondError(w, http.StatusUnauthorized, "token revoked")
	default:
		respondError(w, http.StatusInternalServerError, "internal server error")
	}
}
