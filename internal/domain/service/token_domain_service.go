package service

import (
	"context"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// Ensure it satisfies the interface in token_service.go
var _ TokenService = (*tokenDomainService)(nil)

type tokenDomainService struct {
	repo   repository.TokenRepository
	crypto CryptoService
	log    logger.Logger
	// add cfg fields if needed later (TTL, etc.)
}

func NewTokenDomainService(
	repo repository.TokenRepository,
	crypto CryptoService,
	log logger.Logger,
) TokenService {
	return &tokenDomainService{
		repo:   repo,
		crypto: crypto,
		log:    log,
	}
}

// ---- Minimal stubs to compile; replace with real logic as you go ----

func (s *tokenDomainService) IssueTokenPair(
	ctx context.Context,
	tenantID string,
	agentID string,
	deviceFingerprint string,
	scope []string,
	metadata map[string]interface{},
) (refreshToken *models.Token, accessToken *models.Token, err error) {
	refreshToken, err = s.generateRefreshToken(ctx, tenantID, agentID, scope)
	if err != nil {
		return nil, nil, err
	}

	accessToken, err = s.GenerateAccessToken(ctx, refreshToken, scope)
	if err != nil {
		return nil, nil, err
	}

	return refreshToken, accessToken, nil
}

func (s *tokenDomainService) RefreshToken(
	ctx context.Context,
	refreshTokenString string,
	requestedScope []string,
) (newRefreshToken *models.Token, accessToken *models.Token, err error) {
	// 1. Verify the old refresh token
	oldRefreshToken, err := s.VerifyToken(ctx, refreshTokenString, constants.TokenTypeRefresh, "")
	if err != nil {
		return nil, nil, err
	}

	// 2. Check if it has been revoked
	isRevoked, err := s.IsTokenRevoked(ctx, oldRefreshToken.JTI)
	if err != nil {
		return nil, nil, err
	}
	if isRevoked {
		return nil, nil, errors.ErrTokenRevoked("refresh_token", oldRefreshToken.JTI)
	}

	// 3. Generate a new access token and a new refresh token
	accessToken, err = s.GenerateAccessToken(ctx, oldRefreshToken, requestedScope)
	if err != nil {
		return nil, nil, err
	}

	newRefreshToken, err = s.generateRefreshToken(ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID, strings.Split(oldRefreshToken.Scope, " "))
	if err != nil {
		return nil, nil, err
	}

	// 4. Revoke the old refresh token
	err = s.repo.Revoke(ctx, oldRefreshToken.JTI, "rotated")
	if err != nil {
		return nil, nil, err
	}

	// 5. Save the new refresh token
	err = s.repo.Save(ctx, newRefreshToken)
	if err != nil {
		return nil, nil, err
	}

	return newRefreshToken, accessToken, nil
}

func (s *tokenDomainService) VerifyToken(
	ctx context.Context,
	tokenString string,
	tokenType constants.TokenType, // or constants.TokenType depending on your interface
	tenantID string,
) (*models.Token, error) {
	claims, err := s.crypto.VerifyJWT(ctx, tokenString, tenantID)
	if err != nil {
		return nil, err
	}

	// For now, we'll just extract the JTI and look it up.
	// A more complete implementation would validate all claims.
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, errors.ErrInvalidRequest("missing jti")
	}

	return s.repo.FindByJTI(ctx, jti)
}

func (s *tokenDomainService) RevokeToken(
	ctx context.Context,
	jti string,
	tenantID string,
	reason string,
) error {
	return s.repo.Revoke(ctx, jti, reason)
}

func (s *tokenDomainService) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return s.repo.IsRevoked(ctx, jti)
}

func (s *tokenDomainService) GenerateAccessToken(
	ctx context.Context,
	refreshToken *models.Token,
	requestedScope []string,
) (*models.Token, error) {
	// For now, we'll just generate a new token with the same claims.
	// A more complete implementation would handle scope reduction.
	return s.generateAccessToken(ctx, refreshToken.TenantID, refreshToken.DeviceID, requestedScope)
}

func (s *tokenDomainService) generateAccessToken(ctx context.Context, tenantID, deviceID string, scope []string) (*models.Token, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": deviceID,
		"jti": uuid.New().String(),
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
		"iss": "cbc-auth-service",
		"aud": "cbc-api",
		"tid": tenantID,
		"scp": scope,
	}

	_, _, err := s.crypto.GenerateJWT(ctx, tenantID, claims)
	if err != nil {
		return nil, err
	}

	return &models.Token{
		JTI:        claims["jti"].(string),
		TenantID:   tenantID,
		DeviceID:   deviceID,
		Scope:      strings.Join(scope, " "),
		TokenType:  constants.TokenTypeAccess,
		IssuedAt:   now,
		ExpiresAt:  time.Unix(claims["exp"].(int64), 0),
	}, nil
}

func (s *tokenDomainService) generateRefreshToken(ctx context.Context, tenantID, deviceID string, scope []string) (*models.Token, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": deviceID,
		"jti": uuid.New().String(),
		"iat": now.Unix(),
		"exp": now.Add(720 * time.Hour).Unix(),
		"iss": "cbc-auth-service",
		"aud": "cbc-auth-service",
		"tid": tenantID,
		"scp": scope,
	}

	_, _, err := s.crypto.GenerateJWT(ctx, tenantID, claims)
	if err != nil {
		return nil, err
	}

	return &models.Token{
		JTI:        claims["jti"].(string),
		TenantID:   tenantID,
		DeviceID:   deviceID,
		Scope:      strings.Join(scope, " "),
		TokenType:  constants.TokenTypeRefresh,
		IssuedAt:   now,
		ExpiresAt:  time.Unix(claims["exp"].(int64), 0),
	}, nil
}

func (s *tokenDomainService) ValidateTokenClaims(
	ctx context.Context,
	token *models.Token,
	validationContext map[string]interface{},
) (bool, error) {
	return false, errors.ErrServerError("ValidateTokenClaims not implemented yet")
}

func (s *tokenDomainService) IntrospectToken(
	ctx context.Context,
	tokenString string,
	tokenTypeHint string,
) (*models.TokenIntrospection, error) {
	return nil, errors.ErrServerError("IntrospectToken not implemented yet")
}

func (s *tokenDomainService) CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error) {
	return 0, errors.ErrServerError("CleanupExpiredTokens not implemented yet")
}

func (s *tokenDomainService) IssueToken(ctx context.Context, tenantID, subject string, scope []string) (*models.Token, error) {
	return s.generateAccessToken(ctx, tenantID, subject, scope)
}
