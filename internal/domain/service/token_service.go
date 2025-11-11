// Package service 定义领域服务接口
// Token 领域服务接口 - 负责 Token 相关的核心业务逻辑
package service

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
)

// TokenService defines the core business logic for token operations, including issuance, refresh, validation, and revocation.
// TokenService 定义了令牌相关的核心业务方法，包括颁发、刷新、验证、吊销等操作。
type TokenService interface {
	// IssueTokenPair issues a new pair of a long-lived refresh token and a short-lived access token.
	// Used in device registration or MGR-proxied registration scenarios.
	// IssueTokenPair 颁发 Refresh Token 和 Access Token 对。用于设备注册或 MGR 代理注册场景。
	IssueTokenPair(
		ctx context.Context,
		tenantID string,
		agentID string,
		deviceFingerprint string,
		scope []string,
		metadata map[string]interface{},
	) (refreshToken *models.Token, accessToken *models.Token, err error)

	// IssueToken issues a single token, typically an access token for flows like client credentials.
	// IssueToken 颁发单个令牌，通常是用于客户端凭据等流程的访问令牌。
	IssueToken(ctx context.Context, tenantID, subject string, scope []string) (*models.Token, error)

	// RefreshToken uses a valid refresh token to issue a new access token and, optionally, a new refresh token.
	// Implements a one-time-use refresh token mechanism where the old token is invalidated upon use.
	// RefreshToken 使用 Refresh Token 获取新的 Access Token。实现一次性 Refresh Token 机制（旧 Refresh Token 立即失效）。
	RefreshToken(
		ctx context.Context,
		refreshTokenString string,
		requestedScope []string,
	) (newRefreshToken *models.Token, accessToken *models.Token, err error)

	// VerifyToken validates a token's signature, expiration, and revocation status.
	// VerifyToken 验证 Token 的有效性，检查签名、有效期、吊销状态等。
	VerifyToken(
		ctx context.Context,
		tokenString string,
		tokenType constants.TokenType,
		tenantID string,
	) (*models.Token, error)

	// RevokeToken invalidates a token by adding its JTI to a blacklist.
	// RevokeToken 吊销 Token，将 Token 的 JTI 加入黑名单，使其立即失效。
	RevokeToken(
		ctx context.Context,
		jti string,
		tenantID string,
		reason string,
	) error

	// IsTokenRevoked checks if a token has been revoked by consulting the blacklist.
	// IsTokenRevoked 检查 Token 是否已被吊销，查询黑名单（Redis + PostgreSQL 双重检查）。
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)

	// GenerateAccessToken creates a new short-lived access token based on the information from a refresh token.
	// GenerateAccessToken 基于 Refresh Token 的信息生成短效 Access Token。
	GenerateAccessToken(
		ctx context.Context,
		refreshToken *models.Token,
		requestedScope []string,
	) (*models.Token, error)

	// ValidateTokenClaims performs business rule validation on token claims.
	// Checks against constraints like device fingerprint matching, IP whitelisting, etc.
	// ValidateTokenClaims 验证 Token Claims 的业务规则，检查 Token 是否符合业务约束（如设备指纹匹配、IP 白名单等）。
	ValidateTokenClaims(
		ctx context.Context,
		token *models.Token,
		validationContext map[string]interface{},
	) (bool, error)

	// IntrospectToken provides an introspection endpoint for tokens, for services that cannot perform local validation.
	// Conforms to RFC 7662.
	// IntrospectToken 为不支持本地验签的业务服务提供 Token 验证接口。
	IntrospectToken(
		ctx context.Context,
		tokenString string,
		tokenTypeHint string,
	) (*models.TokenIntrospection, error)

	// CleanupExpiredTokens periodically removes expired token metadata from the database.
	// CleanupExpiredTokens 定期清理数据库中已过期的 Token 记录。
	CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error)
}

// TokenServiceConfig holds configuration settings for the token service.
// TokenServiceConfig Token 服务配置。
type TokenServiceConfig struct {
	// RefreshTokenTTL is the lifetime of a refresh token in seconds.
	// RefreshTokenTTL Refresh Token 有效期（秒）。
	RefreshTokenTTL int64

	// AccessTokenTTL is the lifetime of an access token in seconds.
	// AccessTokenTTL Access Token 有效期（秒）。
	AccessTokenTTL int64

	// EnableOneTimeRefreshToken enables or disables the one-time-use refresh token rotation mechanism.
	// EnableOneTimeRefreshToken 是否启用一次性 Refresh Token。
	EnableOneTimeRefreshToken bool

	// AllowedClockSkew is the acceptable clock skew in seconds for validating token timestamps (e.g., 'exp', 'nbf').
	// AllowedClockSkew 允许的时钟偏差（秒）。
	AllowedClockSkew int64

	// DefaultScope is the default scope assigned to a token if none is requested.
	// DefaultScope 默认权限范围。
	DefaultScope []string
}

//Personal.AI order the ending
