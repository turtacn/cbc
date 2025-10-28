// Package service 定义领域服务接口
// 加密服务接口 - 负责 JWT 生成、验证、密钥管理等加密相关操作
package service

// KeyMetadata 密钥元数据
type KeyMetadata struct {
	// KeyID 密钥标识符
	KeyID string

	// TenantID 租户标识符
	TenantID string

	// Algorithm 加密算法（如 RS256）
	Algorithm string

	// KeySize 密钥长度（如 4096）
	KeySize int

	// Status 密钥状态（active, deprecated, revoked）
	Status string

	// CreatedAt 创建时间
	CreatedAt int64

	// ExpiresAt 过期时间
	ExpiresAt int64

	// RotatedAt 轮换时间
	RotatedAt int64

	// RevokedAt 吊销时间
	RevokedAt int64

	// RevokedReason 吊销原因
	RevokedReason string
}

// CryptoServiceConfig 加密服务配置
type CryptoServiceConfig struct {
	// SigningAlgorithm JWT 签名算法（默认 RS256）
	SigningAlgorithm string

	// KeySize RSA 密钥长度（默认 4096）
	KeySize int

	// KeyRotationPeriod 密钥轮换周期（秒）
	KeyRotationPeriod int64

	// PublicKeyCacheTTL 公钥缓存 TTL（秒）
	PublicKeyCacheTTL int64

	// VaultPath Vault 密钥存储路径
	VaultPath string

	// EnableLocalCache 是否启用本地缓存（L1）
	EnableLocalCache bool

	// AllowedAlgorithms 允许的签名算法列表
	AllowedAlgorithms []string
}

//Personal.AI order the ending
