package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/authservice/auth-service/internal/domain"
	"github.com/google/uuid"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// UserIDKey is the context key for the authenticated user's ID.
	UserIDKey contextKey = "user_id"
	// UserEmailKey is the context key for the authenticated user's email.
	UserEmailKey contextKey = "user_email"
	// UserUsernameKey is the context key for the authenticated user's username.
	UserUsernameKey contextKey = "user_username"
)

// JWTAuth returns middleware that validates JWT access tokens.
// It extracts the token from the Authorization header (Bearer scheme),
// validates it, and injects user claims into the request context.
func JWTAuth(tokenSvc domain.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			claims, err := tokenSvc.ValidateAccessToken(parts[1])
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, UserEmailKey, claims.Email)
			ctx = context.WithValue(ctx, UserUsernameKey, claims.Username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext extracts the user ID from the request context.
func UserIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(UserIDKey).(uuid.UUID)
	return id, ok
}
