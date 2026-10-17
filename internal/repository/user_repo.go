package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/authservice/auth-service/internal/domain"
	"github.com/google/uuid"
)

// UserRepository implements domain.UserRepository using PostgreSQL.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository returns a new UserRepository backed by the given connection pool.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// Create inserts a new user into the database.
// Returns domain.ErrUserAlreadyExists if a unique constraint is violated.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (id, email, username, password, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.pool.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Username,
		user.Password,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrUserAlreadyExists
		}
		return fmt.Errorf("inserting user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by their unique ID.
// Returns domain.ErrUserNotFound if no matching row exists.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, username, password, is_active, created_at, updated_at
		FROM users
		WHERE id = $1`

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("querying user by id: %w", err)
	}

	return user, nil
}

// GetByEmail retrieves a user by their email address.
// Returns domain.ErrUserNotFound if no matching row exists.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, username, password, is_active, created_at, updated_at
		FROM users
		WHERE email = $1`

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("querying user by email: %w", err)
	}

	return user, nil
}

// GetByUsername retrieves a user by their username.
// Returns domain.ErrUserNotFound if no matching row exists.
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	query := `
		SELECT id, email, username, password, is_active, created_at, updated_at
		FROM users
		WHERE username = $1`

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.Password,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("querying user by username: %w", err)
	}

	return user, nil
}

// Update modifies an existing user's mutable fields.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	query := `
		UPDATE users
		SET email = $1, username = $2, is_active = $3, updated_at = $4
		WHERE id = $5`

	_, err := r.pool.Exec(ctx, query,
		user.Email,
		user.Username,
		user.IsActive,
		user.UpdatedAt,
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("updating user: %w", err)
	}

	return nil
}

// Delete removes a user by their ID.
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("deleting user: %w", err)
	}

	return nil
}
