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
	repo repository.TokenRepository
	kms  KeyManagementService
	log  logger.Logger
	// add cfg fields if needed later (TTL, etc.)
}

// NewTokenDomainService creates a new instance of the token domain service.
// NewTokenDomainService 创建令牌领域服务的新实例。
func NewTokenDomainService(
	repo repository.TokenRepository,
	kms KeyManagementService,
	log logger.Logger,
) TokenService {
	return &tokenDomainService{
		repo: repo,
		kms:  kms,
		log:  log,
	}
}

// IssueTokenPair generates and persists a new pair of refresh and access tokens.
// IssueTokenPair 生成并持久化一对新的刷新和访问令牌。
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

	if trustLevel, ok := metadata["trust_level"].(string); ok {
		if refreshToken.Metadata == nil {
			refreshToken.Metadata = make(map[string]interface{})
		}
		refreshToken.Metadata["device_trust_level"] = trustLevel
	}

	accessToken, err = s.GenerateAccessToken(ctx, refreshToken, nil, strings.Join(scope, " "), "")
	if err != nil {
		return nil, nil, err
	}

	return refreshToken, accessToken, nil
}

// RefreshToken validates an old refresh token and issues a new pair of refresh and access tokens.
// It also revokes the old refresh token to enforce one-time use.
// RefreshToken 验证旧的刷新令牌并颁发一对新的刷新和访问令牌。
// 它还会撤销旧的刷新令牌以强制一次性使用。
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
	accessToken, err = s.GenerateAccessToken(ctx, oldRefreshToken, nil, strings.Join(requestedScope, " "), "")
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

// VerifyToken validates the signature and claims of a JWT string and returns the corresponding token metadata.
// VerifyToken 验证 JWT 字符串的签名和声明，并返回相应的令牌元数据。
func (s *tokenDomainService) VerifyToken(
	ctx context.Context,
	tokenString string,
	tokenType constants.TokenType,
	tenantID string,
) (*models.Token, error) {
	claims, err := s.kms.VerifyJWT(ctx, tokenString, tenantID)
	if err != nil {
		return nil, err
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, errors.ErrInvalidRequest("missing jti")
	}

	return s.repo.FindByJTI(ctx, jti)
}

// RevokeToken marks a token as revoked in the repository.
// RevokeToken 在存储库中将令牌标记为已撤销。
func (s *tokenDomainService) RevokeToken(
	ctx context.Context,
	jti string,
	tenantID string,
	reason string,
) error {
	return s.repo.Revoke(ctx, jti, reason)
}

// IsTokenRevoked checks if a token has been revoked.
// IsTokenRevoked 检查令牌是否已被撤销。
func (s *tokenDomainService) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return s.repo.IsRevoked(ctx, jti)
}

// GenerateAccessToken creates a new access token based on a refresh token and requested scopes.
// GenerateAccessToken 基于刷新令牌和请求的范围创建一个新的访问令牌。
func (s *tokenDomainService) GenerateAccessToken(
	ctx context.Context,
	refreshToken *models.Token,
	ttl *time.Duration,
	scope string,
	trustLevel string,
) (*models.Token, error) {
	return s.generateAccessToken(ctx, refreshToken.TenantID, refreshToken.DeviceID, ttl, scope, trustLevel)
}

// generateAccessToken is a helper function to create and sign an access token.
// generateAccessToken 是一个用于创建和签署访问令牌的辅助函数。
func (s *tokenDomainService) generateAccessToken(ctx context.Context, tenantID, deviceID string, ttl *time.Duration, scope string, trustLevel string) (*models.Token, error) {
	now := time.Now()
	// Default TTL if not provided
	if ttl == nil {
		defaultTTL := 15 * time.Minute
		ttl = &defaultTTL
	}
	claims := jwt.MapClaims{
		"sub":                deviceID,
		"jti":                uuid.New().String(),
		"iat":                now.Unix(),
		"exp":                now.Add(*ttl).Unix(),
		"iss":                "cbc-auth-service",
		"aud":                "cbc-api",
		"tid":                tenantID,
		"scp":                scope,
		"device_trust_level": trustLevel,
	}

	_, _, err := s.kms.GenerateJWT(ctx, tenantID, claims)
	if err != nil {
		return nil, err
	}

	return &models.Token{
		JTI:       claims["jti"].(string),
		TenantID:  tenantID,
		DeviceID:  deviceID,
		Scope:     scope,
		TokenType: constants.TokenTypeAccess,
		IssuedAt:  now,
		ExpiresAt: time.Unix(claims["exp"].(int64), 0),
	}, nil
}

// generateRefreshToken is a helper function to create and sign a refresh token.
// generateRefreshToken 是一个用于创建和签署刷新令牌的辅助函数。
func (s *tokenDomainService) generateRefreshToken(ctx context.Context, tenantID, deviceID string, scope []string) (*models.Token, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": deviceID,
		"jti": uuid.New().String(),
		"iat": now.Unix(),
		"exp": now.Add(720 * time.Hour).Unix(), // 30 days
		"iss": "cbc-auth-service",
		"aud": "cbc-auth-service",
		"tid": tenantID,
		"scp": scope,
	}

	_, _, err := s.kms.GenerateJWT(ctx, tenantID, claims)
	if err != nil {
		return nil, err
	}

	return &models.Token{
		JTI:       claims["jti"].(string),
		TenantID:  tenantID,
		DeviceID:  deviceID,
		Scope:     strings.Join(scope, " "),
		TokenType: constants.TokenTypeRefresh,
		IssuedAt:  now,
		ExpiresAt: time.Unix(claims["exp"].(int64), 0),
	}, nil
}

// ValidateTokenClaims performs a deeper validation of a token's claims against a given context. (Not implemented)
// ValidateTokenClaims 根据给定上下文对令牌的声明执行更深入的验证。（未实现）
func (s *tokenDomainService) ValidateTokenClaims(
	ctx context.Context,
	token *models.Token,
	validationContext map[string]interface{},
) (bool, error) {
	return false, errors.ErrServerError("ValidateTokenClaims not implemented yet")
}

// IntrospectToken provides information about a token, conforming to RFC 7662. (Not implemented)
// IntrospectToken 提供有关令牌的信息，符合 RFC 7662。（未实现）
func (s *tokenDomainService) IntrospectToken(
	ctx context.Context,
	tokenString string,
	tokenTypeHint string,
) (*models.TokenIntrospection, error) {
	return nil, errors.ErrServerError("IntrospectToken not implemented yet")
}

// CleanupExpiredTokens removes expired token metadata from the persistence layer. (Not implemented)
// CleanupExpiredTokens 从持久层中删除过期的令牌元数据。（未实现）
func (s *tokenDomainService) CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error) {
	return 0, errors.ErrServerError("CleanupExpiredTokens not implemented yet")
}

// IssueToken issues a simple token (e.g., for client credentials flow) without a refresh token.
// IssueToken 颁发一个简单的令牌（例如，用于客户端凭据流），没有刷新令牌。
func (s *tokenDomainService) IssueToken(ctx context.Context, tenantID, subject string, scope []string) (*models.Token, error) {
	return s.generateAccessToken(ctx, tenantID, subject, nil, strings.Join(scope, " "), "") // No trust level needed for this flow
}
