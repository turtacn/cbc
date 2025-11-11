// Package service 定义领域服务接口
// 加密服务接口 - 负责 JWT 生成、验证、密钥管理等加密相关操作
package service

// KeyMetadata holds descriptive information about a cryptographic key.
// KeyMetadata 密钥元数据。
type KeyMetadata struct {
	// KeyID is the unique identifier for the key.
	// KeyID 密钥标识符。
	KeyID string

	// TenantID is the identifier of the tenant that owns the key.
	// TenantID 租户标识符。
	TenantID string

	// Algorithm is the cryptographic algorithm of the key (e.g., "RS256").
	// Algorithm 加密算法（如 RS256）。
	Algorithm string

	// KeySize is the size of the key in bits (e.g., 4096).
	// KeySize 密钥长度（如 4096）。
	KeySize int

	// Status is the lifecycle status of the key (e.g., "active", "deprecated", "revoked").
	// Status 密钥状态（active, deprecated, revoked）。
	Status string

	// CreatedAt is the Unix timestamp of when the key was created.
	// CreatedAt 创建时间。
	CreatedAt int64

	// ExpiresAt is the Unix timestamp of when the key is scheduled to expire.
	// ExpiresAt 过期时间。
	ExpiresAt int64

	// RotatedAt is the Unix timestamp of the last time the key was rotated.
	// RotatedAt 轮换时间。
	RotatedAt int64

	// RevokedAt is the Unix timestamp of when the key was revoked.
	// RevokedAt 吊销时间。
	RevokedAt int64

	// RevokedReason is the reason the key was revoked.
	// RevokedReason 吊销原因。
	RevokedReason string
}

// CryptoServiceConfig holds configuration settings for the cryptographic service.
// CryptoServiceConfig 加密服务配置。
type CryptoServiceConfig struct {
	// SigningAlgorithm is the default algorithm for signing JWTs (e.g., "RS256").
	// SigningAlgorithm JWT 签名算法（默认 RS256）。
	SigningAlgorithm string

	// KeySize is the default size in bits for new RSA keys (e.g., 4096).
	// KeySize RSA 密钥长度（默认 4096）。
	KeySize int

	// KeyRotationPeriod is the automatic key rotation period in seconds.
	// KeyRotationPeriod 密钥轮换周期（秒）。
	KeyRotationPeriod int64

	// PublicKeyCacheTTL is the time-to-live in seconds for caching public keys.
	// PublicKeyCacheTTL 公钥缓存 TTL（秒）。
	PublicKeyCacheTTL int64

	// VaultPath is the storage path for keys in HashiCorp Vault.
	// VaultPath Vault 密钥存储路径。
	VaultPath string

	// EnableLocalCache enables or disables L1 in-memory caching.
	// EnableLocalCache 是否启用本地缓存（L1）。
	EnableLocalCache bool

	// AllowedAlgorithms is a list of signature algorithms that are permitted for token validation.
	// AllowedAlgorithms 允许的签名算法列表。
	AllowedAlgorithms []string
}

//Personal.AI order the ending
