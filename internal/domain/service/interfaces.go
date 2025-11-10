package service

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/models"
)

//go:generate mockery --name KeyProvider --output mocks --outpkg mocks
// KeyProvider defines the interface for physical key operations.
type KeyProvider interface {
	GenerateKey(ctx context.Context, keySpec models.KeySpec) (kid, providerRef string, publicKey *rsa.PublicKey, err error)
	Sign(ctx context.Context, providerRef string, digest []byte) (signature []byte, err error)
	GetPublicKey(ctx context.Context, providerRef string) (*rsa.PublicKey, error)
	Backup(ctx context.Context, providerRef string) (encryptedBlob []byte, err error)
	Restore(ctx context.Context, encryptedBlob []byte) (providerRef string, err error)
}

//go:generate mockery --name KeyManagementService --output mocks --outpkg mocks
// KeyManagementService defines the interface for managing the key lifecycle.
type KeyManagementService interface {
	RotateTenantKey(ctx context.Context, tenantID string, cdnManager CDNCacheManager) (string, error)
	GetTenantPublicKeys(ctx context.Context, tenantID string) (map[string]*rsa.PublicKey, error)
	CompromiseKey(ctx context.Context, tenantID, kid, reason string, cdnManager CDNCacheManager) error
	GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (tokenString, keyID string, err error)
	VerifyJWT(ctx context.Context, tokenString, tenantID string) (jwt.MapClaims, error)
}

// RateLimitDimension defines the logical type of rate limiting.
type RateLimitDimension string

const (
	RateLimitDimensionTenant RateLimitDimension = "tenant"
	RateLimitDimensionUser   RateLimitDimension = "user"
	RateLimitDimensionToken  RateLimitDimension = "token"
	RateLimitDimensionDevice RateLimitDimension = "device"
	RateLimitDimensionIP     RateLimitDimension = "ip"
	RateLimitDimensionGlobal RateLimitDimension = "global"
)

// RateLimitService defines the interface for rate limiting operations.
type RateLimitService interface {
	Allow(
		ctx context.Context,
		dimension RateLimitDimension,
		key string,
		identifier string,
	) (allowed bool, remaining int, resetAt time.Time, err error)
}

// TokenBlacklistStore defines the interface for token blacklist operations.
type TokenBlacklistStore interface {
	Revoke(ctx context.Context, tenantID, jti string, exp time.Time) error
	IsRevoked(ctx context.Context, tenantID, jti string) (bool, error)
}

// AuditService defines the interface for logging security audit events.
type AuditService interface {
	LogEvent(ctx context.Context, event models.AuditEvent) error
}

// DeviceAuthStore defines the interface for storing and managing device authorization sessions.
type DeviceAuthStore interface {
	CreateSession(ctx context.Context, session *models.DeviceAuthSession) error
	GetSessionByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceAuthSession, error)
	GetSessionByUserCode(ctx context.Context, userCode string) (*models.DeviceAuthSession, error)
	ApproveSession(ctx context.Context, userCode, tenantID, subject string) error
	DenySession(ctx context.Context, userCode string) error
	TouchPoll(ctx context.Context, deviceCode string) error
}

// PolicyService defines the interface for policy-based decisions.
type PolicyService interface {
	// EvaluateTrustLevel evaluates the trust level of a device based on its fingerprint.
	EvaluateTrustLevel(ctx context.Context, fingerprint string) (string, error)
	// EvaluateContextAccess evaluates if access should be granted based on the token claims and context.
	EvaluateContextAccess(ctx context.Context, claims jwt.MapClaims, e_context map[string]interface{}) (bool, error)
}

// MgrKeyFetcher defines the interface for fetching MGR public keys.
type MgrKeyFetcher interface {
	GetMgrPublicKey(ctx context.Context, clientID, kid string) (*rsa.PublicKey, error)
}

// CDNCacheManager defines the interface for CDN cache management.
type CDNCacheManager interface {
	PurgeTenantJWKS(ctx context.Context, tenantID string) error
	PurgePath(ctx context.Context, path string) error
}

//go:generate mockery --name KeyLifecycleRegistry --output mocks --outpkg mocks
// KeyLifecycleRegistry defines the interface for logging key lifecycle events.
type KeyLifecycleRegistry interface {
	LogEvent(ctx context.Context, event models.KLREvent) error
}

//go:generate mockery --name PolicyEngine --output mocks --outpkg mocks
// PolicyEngine defines the interface for checking policies.
type PolicyEngine interface {
	CheckKeyGeneration(ctx context.Context, policy models.PolicyRequest) error
}

//go:generate mockery --name RiskOracle --output mocks --outpkg mocks
// RiskOracle defines the interface for obtaining tenant risk profiles.
type RiskOracle interface {
	GetTenantRisk(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error)
}
