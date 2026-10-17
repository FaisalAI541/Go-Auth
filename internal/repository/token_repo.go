package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/authservice/auth-service/internal/domain"
	"github.com/google/uuid"
)

// TokenRepository implements domain.TokenRepository using PostgreSQL.
type TokenRepository struct {
	pool *pgxpool.Pool
}

// NewTokenRepository returns a new TokenRepository backed by the given connection pool.
func NewTokenRepository(pool *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{pool: pool}
}

// Create inserts a new refresh token into the database.
func (r *TokenRepository) Create(ctx context.Context, token *domain.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5)`

	_, err := r.pool.Exec(ctx, query,
		token.ID,
		token.UserID,
		token.TokenHash,
		token.ExpiresAt,
		token.Revoked,
	)
	if err != nil {
		return fmt.Errorf("inserting refresh token: %w", err)
	}

	return nil
}

// GetByID retrieves a valid (non-revoked, non-expired) refresh token by its ID.
// Returns domain.ErrTokenInvalid if the token is not found, revoked, or expired.
func (r *TokenRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, expires_at, created_at, revoked
		FROM refresh_tokens
		WHERE id = $1 AND revoked = false AND expires_at > NOW()`

	token := &domain.RefreshToken{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.Revoked,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrTokenInvalid
		}
		return nil, fmt.Errorf("querying refresh token by id: %w", err)
	}

	return token, nil
}

// RevokeByUserID revokes all active refresh tokens for a given user.
func (r *TokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE user_id = $1 AND revoked = false`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("revoking tokens by user id: %w", err)
	}

	return nil
}

// RevokeByID revokes a single refresh token by its ID.
func (r *TokenRepository) RevokeByID(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked = true
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("revoking token by id: %w", err)
	}

	return nil
}

// DeleteExpired removes all expired or revoked refresh tokens from the database.
// It returns the number of rows deleted.
func (r *TokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked = true`

	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("deleting expired tokens: %w", err)
	}

	return result.RowsAffected(), nil
}
