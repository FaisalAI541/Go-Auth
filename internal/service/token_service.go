package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/authservice/auth-service/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenConfig holds the configuration for JWT token generation and validation.
type TokenConfig struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	Issuer        string
}

// JWTTokenService implements domain.TokenService using JWT tokens.
type JWTTokenService struct {
	cfg TokenConfig
}

// NewJWTTokenService creates a new JWTTokenService with the given configuration.
func NewJWTTokenService(cfg TokenConfig) *JWTTokenService {
	return &JWTTokenService{cfg: cfg}
}

// GenerateAccessToken creates a signed JWT access token for the given user.
func (s *JWTTokenService) GenerateAccessToken(user *domain.User) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":      user.ID.String(),
		"email":    user.Email,
		"username": user.Username,
		"iss":      s.cfg.Issuer,
		"exp":      now.Add(s.cfg.AccessExpiry).Unix(),
		"iat":      now.Unix(),
		"jti":      uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(s.cfg.AccessSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, nil
}

// GenerateRefreshToken creates a signed JWT refresh token for the given user.
// It returns the signed token string and the unique token ID embedded in the claims.
func (s *JWTTokenService) GenerateRefreshToken(user *domain.User) (string, uuid.UUID, error) {
	now := time.Now()
	tokenID := uuid.New()

	claims := jwt.MapClaims{
		"sub":      user.ID.String(),
		"token_id": tokenID.String(),
		"iss":      s.cfg.Issuer,
		"exp":      now.Add(s.cfg.RefreshExpiry).Unix(),
		"iat":      now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(s.cfg.RefreshSecret))
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return signedToken, tokenID, nil
}

// ValidateAccessToken parses and validates a JWT access token string.
// It returns the extracted claims or an appropriate domain error.
func (s *JWTTokenService) ValidateAccessToken(tokenStr string) (*domain.AccessTokenClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.AccessSecret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domain.ErrTokenExpired
		}
		return nil, domain.ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, domain.ErrTokenInvalid
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing or invalid 'sub' claim", domain.ErrTokenInvalid)
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user ID in token: %v", domain.ErrTokenInvalid, err)
	}

	email, ok := claims["email"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing or invalid 'email' claim", domain.ErrTokenInvalid)
	}

	username, ok := claims["username"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing or invalid 'username' claim", domain.ErrTokenInvalid)
	}

	return &domain.AccessTokenClaims{
		UserID:   userID,
		Email:    email,
		Username: username,
	}, nil
}

// ValidateRefreshToken parses and validates a JWT refresh token string.
// It returns the extracted claims or an appropriate domain error.
func (s *JWTTokenService) ValidateRefreshToken(tokenStr string) (*domain.RefreshTokenClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.cfg.RefreshSecret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, domain.ErrTokenExpired
		}
		return nil, domain.ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, domain.ErrTokenInvalid
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing or invalid 'sub' claim", domain.ErrTokenInvalid)
	}

	userID, err := uuid.Parse(sub)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid user ID in token: %v", domain.ErrTokenInvalid, err)
	}

	tokenIDStr, ok := claims["token_id"].(string)
	if !ok {
		return nil, fmt.Errorf("%w: missing or invalid 'token_id' claim", domain.ErrTokenInvalid)
	}

	tokenID, err := uuid.Parse(tokenIDStr)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid token ID in token: %v", domain.ErrTokenInvalid, err)
	}

	return &domain.RefreshTokenClaims{
		UserID:  userID,
		TokenID: tokenID,
	}, nil
}
