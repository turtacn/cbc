package service

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/models"
)

//go:generate mockery --name KeyProvider --output mocks --outpkg mocks
// KeyProvider defines the interface for physical cryptographic key operations, abstracting the underlying hardware or service (e.g., HSM, Vault).
// KeyProvider 定义了物理加密密钥操作的接口，抽象了底层硬件或服务（例如，HSM、Vault）。
type KeyProvider interface {
	// GenerateKey creates a new cryptographic key according to the given specifications.
	// It returns the new key's ID, a provider-specific reference, and the public key.
	// GenerateKey 根据给定的规范创建一个新的加密密钥。
	// 它返回新密钥的 ID、提供者特定的引用和公钥。
	GenerateKey(ctx context.Context, keySpec models.KeySpec) (kid, providerRef string, publicKey *rsa.PublicKey, err error)

	// Sign uses the private key identified by providerRef to sign a digest.
	// Sign 使用 providerRef 标识的私钥对摘要进行签名。
	Sign(ctx context.Context, providerRef string, digest []byte) (signature []byte, err error)

	// GetPublicKey retrieves the public key corresponding to the private key identified by providerRef.
	// GetPublicKey 检索与 providerRef 标识的私钥对应的公钥。
	GetPublicKey(ctx context.Context, providerRef string) (*rsa.PublicKey, error)

	// Backup creates an encrypted backup of the key material.
	// Backup 创建密钥材料的加密备份。
	Backup(ctx context.Context, providerRef string) (encryptedBlob []byte, err error)

	// Restore restores a key from an encrypted backup.
	// Restore 从加密备份中恢复密钥。
	Restore(ctx context.Context, encryptedBlob []byte) (providerRef string, err error)
}

//go:generate mockery --name KeyManagementService --output mocks --outpkg mocks
// KeyManagementService defines the interface for managing the logical lifecycle of cryptographic keys.
// KeyManagementService 定义了管理加密密钥逻辑生命周期的接口。
type KeyManagementService interface {
	// RotateTenantKey initiates a key rotation for a tenant, creating a new active key and deprecating the old one.
	// RotateTenantKey 为租户启动密钥轮换，创建一个新的活动密钥并弃用旧密钥。
	RotateTenantKey(ctx context.Context, tenantID string, cdnManager CDNCacheManager) (string, error)

	// GetTenantPublicKeys retrieves all public keys (active and deprecated) for a tenant, typically for JWKS endpoint.
	// GetTenantPublicKeys 检索租户的所有公钥（活动的和已弃用的），通常用于 JWKS 端点。
	GetTenantPublicKeys(ctx context.Context, tenantID string) (map[string]*rsa.PublicKey, error)

	// CompromiseKey marks a key as compromised, revoking it from further use.
	// CompromiseKey 将密钥标记为已泄露，并将其撤销以备将来使用。
	CompromiseKey(ctx context.Context, tenantID, kid, reason string, cdnManager CDNCacheManager) error

	// GenerateJWT creates and signs a new JWT for a tenant using the current active key.
	// GenerateJWT 使用当前活动密钥为租户创建并签署新的 JWT。
	GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (tokenString, keyID string, err error)

	// VerifyJWT validates a JWT's signature and claims against a tenant's public keys.
	// VerifyJWT 根据租户的公钥验证 JWT 的签名和声明。
	VerifyJWT(ctx context.Context, tokenString, tenantID string) (jwt.MapClaims, error)
}

// RateLimitDimension defines the logical type of rate limiting.
// RateLimitDimension 定义了速率限制的逻辑类型。
type RateLimitDimension string

const (
	RateLimitDimensionTenant RateLimitDimension = "tenant" // Per-tenant limit / 每个租户的限制
	RateLimitDimensionUser   RateLimitDimension = "user"   // Per-user limit / 每个用户的限制
	RateLimitDimensionToken  RateLimitDimension = "token"  // Per-token limit / 每个令牌的限制
	RateLimitDimensionDevice RateLimitDimension = "device" // Per-device limit / 每个设备的限制
	RateLimitDimensionIP     RateLimitDimension = "ip"     // Per-IP limit / 每个 IP 的限制
	RateLimitDimensionGlobal RateLimitDimension = "global" // Global system limit / 全局系统限制
)

// RateLimitService defines the interface for rate limiting operations.
// RateLimitService 定义了速率限制操作的接口。
type RateLimitService interface {
	// Allow checks if a request is allowed under the rate limit policy for a given dimension and key.
	// It returns whether the request is allowed, the number of remaining requests, and the time when the limit resets.
	// Allow 检查在给定维度和密钥的速率限制策略下是否允许请求。
	// 它返回是否允许请求、剩余请求数以及限制重置的时间。
	Allow(
		ctx context.Context,
		dimension RateLimitDimension,
		key string,
		identifier string,
	) (allowed bool, remaining int, resetAt time.Time, err error)
}

// TokenBlacklistStore defines the interface for storing and checking revoked tokens.
// TokenBlacklistStore 定义了用于存储和检查已撤销令牌的接口。
type TokenBlacklistStore interface {
	// Revoke adds a token's JTI to the blacklist with an expiration.
	// Revoke 将令牌的 JTI 添加到具有过期时间的黑名单中。
	Revoke(ctx context.Context, tenantID, jti string, exp time.Time) error
	// IsRevoked checks if a token's JTI is in the blacklist.
	// IsRevoked 检查令牌的 JTI 是否在黑名单中。
	IsRevoked(ctx context.Context, tenantID, jti string) (bool, error)
}

// AuditService defines the interface for logging security-sensitive audit events.
// AuditService 定义了用于记录安全敏感审计事件的接口。
type AuditService interface {
	// LogEvent records an audit event.
	// LogEvent 记录审计事件。
	LogEvent(ctx context.Context, event models.AuditEvent) error
}

// DeviceAuthStore defines the interface for managing OAuth 2.0 Device Authorization Grant sessions.
// DeviceAuthStore 定义了用于管理 OAuth 2.0 设备授权授予会话的接口。
type DeviceAuthStore interface {
	// CreateSession stores a new device authorization session.
	// CreateSession 存储新的设备授权会话。
	CreateSession(ctx context.Context, session *models.DeviceAuthSession) error
	// GetSessionByDeviceCode retrieves a session using the device code.
	// GetSessionByDeviceCode 使用设备代码检索会话。
	GetSessionByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceAuthSession, error)
	// GetSessionByUserCode retrieves a session using the user code.
	// GetSessionByUserCode 使用用户代码检索会话。
	GetSessionByUserCode(ctx context.Context, userCode string) (*models.DeviceAuthSession, error)
	// ApproveSession marks a session as approved by the user.
	// ApproveSession 将会话标记为用户已批准。
	ApproveSession(ctx context.Context, userCode, tenantID, subject string) error
	// DenySession marks a session as denied by the user.
	// DenySession 将会话标记为用户已拒绝。
	DenySession(ctx context.Context, userCode string) error
	// TouchPoll updates the last polled timestamp for a session, used for throttling.
	// TouchPoll 更新会话的最后轮询时间戳，用于节流。
	TouchPoll(ctx context.Context, deviceCode string) error
}

// PolicyService defines the interface for making policy-based decisions.
// PolicyService 定义了用于制定基于策略的决策的接口。
type PolicyService interface {
	// EvaluateTrustLevel evaluates the trust level of a device based on its fingerprint.
	// EvaluateTrustLevel 根据设备的指纹评估其信任级别。
	EvaluateTrustLevel(ctx context.Context, fingerprint string) (string, error)
	// EvaluateContextAccess evaluates if access should be granted based on the token claims and request context.
	// EvaluateContextAccess 根据令牌声明和请求上下文评估是否应授予访问权限。
	EvaluateContextAccess(ctx context.Context, claims jwt.MapClaims, e_context map[string]interface{}) (bool, error)
}

// MgrKeyFetcher defines the interface for fetching MGR (Manager) public keys.
// MgrKeyFetcher 定义了用于获取 MGR（管理器）公钥的接口。
type MgrKeyFetcher interface {
	// GetMgrPublicKey retrieves the public key for a given MGR client and key ID.
	// GetMgrPublicKey 检索给定 MGR 客户端和密钥 ID 的公钥。
	GetMgrPublicKey(ctx context.Context, clientID, kid string) (*rsa.PublicKey, error)
}

// CDNCacheManager defines the interface for managing CDN cache invalidation.
// CDNCacheManager 定义了用于管理 CDN 缓存失效的接口。
type CDNCacheManager interface {
	// PurgeTenantJWKS invalidates the cache for a tenant's JWKS endpoint.
	// PurgeTenantJWKS 使租户 JWKS 端点的缓存无效。
	PurgeTenantJWKS(ctx context.Context, tenantID string) error
	// PurgePath invalidates the cache for a specific URL path.
	// PurgePath 使特定 URL 路径的缓存无效。
	PurgePath(ctx context.Context, path string) error
}

//go:generate mockery --name KeyLifecycleRegistry --output mocks --outpkg mocks
// KeyLifecycleRegistry defines the interface for logging key lifecycle events for compliance.
// KeyLifecycleRegistry 定义了用于记录密钥生命周期事件以实现合规性的接口。
type KeyLifecycleRegistry interface {
	// LogEvent records a key lifecycle event (e.g., creation, rotation, revocation).
	// LogEvent 记录密钥生命周期事件（例如，创建、轮换、撤销）。
	LogEvent(ctx context.Context, event models.KLREvent) error
}

//go:generate mockery --name PolicyEngine --output mocks --outpkg mocks
// PolicyEngine defines the interface for checking actions against defined policies.
// PolicyEngine 定义了用于根据定义的策略检查操作的接口。
type PolicyEngine interface {
	// CheckKeyGeneration checks if generating a key with the given specs is allowed by policy.
	// CheckKeyGeneration 检查策略是否允许使用给定规范生成密钥。
	CheckKeyGeneration(ctx context.Context, policy models.PolicyRequest) error
}

//go:generate mockery --name RiskOracle --output mocks --outpkg mocks
// RiskOracle defines the interface for obtaining tenant risk profiles from a risk analysis system.
// RiskOracle 定义了用于从风险分析系统获取租户风险配置文件的接口。
type RiskOracle interface {
	// GetTenantRisk retrieves the current risk profile for a tenant.
	// GetTenantRisk 检索租户的当前风险配置文件。
	GetTenantRisk(ctx context.Context, tenantID string) (*models.TenantRiskProfile, error)
}
