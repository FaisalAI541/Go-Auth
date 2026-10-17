package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

// TokenRepository defines the interface for token persistence.
type TokenRepository interface {
	Create(ctx context.Context, token *RefreshToken) error
	GetByID(ctx context.Context, id uuid.UUID) (*RefreshToken, error)
	RevokeByUserID(ctx context.Context, userID uuid.UUID) error
	RevokeByID(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) (int64, error)
}

// TokenService defines the interface for JWT token operations.
type TokenService interface {
	GenerateAccessToken(user *User) (string, error)
	GenerateRefreshToken(user *User) (string, uuid.UUID, error)
	ValidateAccessToken(tokenStr string) (*AccessTokenClaims, error)
	ValidateRefreshToken(tokenStr string) (*RefreshTokenClaims, error)
}

// AccessTokenClaims represents the claims in an access token.
type AccessTokenClaims struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	Username string    `json:"username"`
}

// RefreshTokenClaims represents the claims in a refresh token.
type RefreshTokenClaims struct {
	UserID  uuid.UUID `json:"user_id"`
	TokenID uuid.UUID `json:"token_id"`
}
