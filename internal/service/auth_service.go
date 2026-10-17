package service

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/authservice/auth-service/internal/domain"
	"github.com/authservice/auth-service/pkg/hash"
	"github.com/google/uuid"
)

// AuthService coordinates user operations, password hashing, and token management.
type AuthService struct {
	userRepo      domain.UserRepository
	tokenRepo     domain.TokenRepository
	tokenSvc      domain.TokenService
	hasher        *hash.Hasher
	logger        *slog.Logger
	refreshExpiry time.Duration
}

// NewAuthService creates a new AuthService with the provided dependencies.
func NewAuthService(
	userRepo domain.UserRepository,
	tokenRepo domain.TokenRepository,
	tokenSvc domain.TokenService,
	hasher *hash.Hasher,
	logger *slog.Logger,
	refreshExpiry time.Duration,
) *AuthService {
	return &AuthService{
		userRepo:      userRepo,
		tokenRepo:     tokenRepo,
		tokenSvc:      tokenSvc,
		hasher:        hasher,
		logger:        logger,
		refreshExpiry: refreshExpiry,
	}
}

// Register creates a new user account and returns an auth response with tokens.
func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.AuthResponse, error) {
	// Validate input.
	if req.Email == "" {
		return nil, fmt.Errorf("%w: email is required", domain.ErrInvalidInput)
	}
	if req.Username == "" {
		return nil, fmt.Errorf("%w: username is required", domain.ErrInvalidInput)
	}
	if len(req.Password) < 8 {
		return nil, fmt.Errorf("%w: password must be at least 8 characters", domain.ErrInvalidInput)
	}

	// Hash the password.
	hashedPassword, err := s.hasher.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the user.
	now := time.Now()
	user := &domain.User{
		ID:        uuid.New(),
		Email:     req.Email,
		Username:  req.Username,
		Password:  hashedPassword,
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	s.logger.Info("user registered successfully",
		slog.String("user_id", user.ID.String()),
		slog.String("email", user.Email),
	)

	// Generate tokens.
	authResp, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}

	return authResp, nil
}

// Login authenticates a user with email and password and returns an auth response with tokens.
func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.AuthResponse, error) {
	// Look up the user by email.
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Warn("login failed: user not found",
			slog.String("email", req.Email),
		)
		return nil, domain.ErrInvalidCredentials
	}

	// Verify the password.
	if !s.hasher.CheckPassword(req.Password, user.Password) {
		s.logger.Warn("login failed: invalid password",
			slog.String("email", req.Email),
		)
		return nil, domain.ErrInvalidCredentials
	}

	// Ensure the user is active.
	if !user.IsActive {
		s.logger.Warn("login failed: user is inactive",
			slog.String("user_id", user.ID.String()),
		)
		return nil, domain.ErrInvalidCredentials
	}

	// Revoke all existing refresh tokens for this user.
	if err := s.tokenRepo.RevokeByUserID(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("failed to revoke existing tokens: %w", err)
	}

	// Generate new tokens.
	authResp, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}

	s.logger.Info("user logged in successfully",
		slog.String("user_id", user.ID.String()),
		slog.String("email", user.Email),
	)

	return authResp, nil
}

// RefreshTokens validates the provided refresh token and issues a new token pair.
func (s *AuthService) RefreshTokens(ctx context.Context, req *domain.RefreshRequest) (*domain.AuthResponse, error) {
	// Validate the refresh token.
	claims, err := s.tokenSvc.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Get the stored token record.
	storedToken, err := s.tokenRepo.GetByID(ctx, claims.TokenID)
	if err != nil {
		s.logger.Warn("refresh failed: stored token not found",
			slog.String("token_id", claims.TokenID.String()),
		)
		return nil, fmt.Errorf("refresh token not found: %w", err)
	}

	// Verify the token hash matches.
	tokenHash := hash.SHA256Hash(req.RefreshToken)
	if tokenHash != storedToken.TokenHash {
		s.logger.Warn("refresh failed: token hash mismatch",
			slog.String("token_id", claims.TokenID.String()),
		)
		return nil, domain.ErrTokenInvalid
	}

	// Revoke the old refresh token.
	if err := s.tokenRepo.RevokeByID(ctx, claims.TokenID); err != nil {
		return nil, fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	// Get the user.
	user, err := s.userRepo.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new token pair.
	authResp, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token pair: %w", err)
	}

	s.logger.Info("tokens refreshed successfully",
		slog.String("user_id", user.ID.String()),
	)

	return authResp, nil
}

// Logout revokes all refresh tokens for the given user.
func (s *AuthService) Logout(ctx context.Context, userID uuid.UUID) error {
	if err := s.tokenRepo.RevokeByUserID(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke tokens on logout: %w", err)
	}

	s.logger.Info("user logged out successfully",
		slog.String("user_id", userID.String()),
	)

	return nil
}

// GetUser retrieves a user by their ID.
func (s *AuthService) GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return user, nil
}

// generateTokenPair creates both access and refresh tokens, stores the refresh
// token hash in the repository, and returns a complete AuthResponse.
func (s *AuthService) generateTokenPair(ctx context.Context, user *domain.User) (*domain.AuthResponse, error) {
	// Generate access token.
	accessToken, err := s.tokenSvc.GenerateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token and get its embedded token ID.
	refreshToken, tokenID, err := s.tokenSvc.GenerateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Hash the refresh token for storage.
	tokenHash := hash.SHA256Hash(refreshToken)

	// Store the refresh token record.
	storedToken := &domain.RefreshToken{
		ID:        tokenID,
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(s.refreshExpiry),
	}

	if err := s.tokenRepo.Create(ctx, storedToken); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &domain.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.refreshExpiry.Seconds()),
	}, nil
}
