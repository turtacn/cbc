// Package service 定义领域服务接口
// 加密服务接口 - 负责 JWT 生成、验证、密钥管理等加密相关操作
package service

import (
	"context"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
)

// CryptoService 加密服务接口
// 提供 JWT 生成、验证、密钥管理等功能，支持多租户密钥隔离
type CryptoService interface {
	// GenerateJWT 生成 JWT
	// 使用租户私钥签名 JWT
	// 参数:
	//   ctx: 上下文对象
	//   tenantID: 租户标识符
	//   claims: JWT Claims
	// 返回:
	//   tokenString: JWT 字符串
	//   keyID: 密钥标识符（用于 JWT Header kid）
	//   error: 错误信息
	GenerateJWT(
		ctx context.Context,
		tenantID string,
		claims jwt.Claims,
	) (tokenString string, keyID string, err error)

	// VerifyJWT 验证 JWT
	// 使用租户公钥验证 JWT 签名和标准声明
	// 参数:
	//   ctx: 上下文对象
	//   tokenString: JWT 字符串
	//   tenantID: 租户标识符
	// 返回:
	//   claims: 解析后的 JWT Claims
	//   error: 错误信息
	VerifyJWT(
		ctx context.Context,
		tokenString string,
		tenantID string,
	) (jwt.MapClaims, error)

	// ParseJWT 解析 JWT（不验证签名）
	// 用于获取 JWT Header 和 Claims 信息
	// 参数:
	//   tokenString: JWT 字符串
	// 返回:
	//   token: 解析后的 JWT Token 对象
	//   error: 错误信息
	ParseJWT(tokenString string) (*jwt.Token, error)

	// GetPublicKey 获取租户公钥
	// 从密钥管理系统（Vault）获取租户的 RSA 公钥
	// 支持多级缓存（L1 本地内存 + L2 Redis）
	// 参数:
	//   ctx: 上下文对象
	//   tenantID: 租户标识符
	//   keyID: 密钥标识符（可选，留空则获取当前活跃密钥）
	// 返回:
	//   publicKey: RSA 公钥
	//   error: 错误信息
	GetPublicKey(
		ctx context.Context,
		tenantID string,
		keyID string,
	) (*rsa.PublicKey, error)

	// GetPrivateKey 获取租户私钥
	// 从密钥管理系统（Vault）获取租户的 RSA 私钥
	// 仅用于 JWT 签名，不缓存
	// 参数:
	//   ctx: 上下文对象
	//   tenantID: 租户标识符
	// 返回:
	//   privateKey: RSA 私钥
	//   keyID: 密钥标识符
	//   error: 错误信息
	GetPrivateKey(
		ctx context.Context,
		tenantID string,
	) (*rsa.PrivateKey, string, error)

	// GetPublicKeyJWKS 获取租户公钥 JWKS 格式
	// 为业务服务提供 JWKS 端点数据
	// 参数:
	//   ctx: 上下文对象
	//   tenantID: 租户标识符
	// 返回:
	//   jwks: JWKS 格式的公钥集合
	//   error: 错误信息
	GetPublicKeyJWKS(
		ctx context.Context,
		tenantID string,
	) (map[string]interface{}, error)

	// RotateKey 轮换租户密钥
	// 生成新密钥对，将旧密钥标记为 deprecated
	// 参数:
	//   ctx: 上下文对象
	//   tenantID: 租户标识符
	// 返回:
	//   newKeyID: 新密钥标识符
	//   error: 错误信息
	RotateKey(ctx context.Context, tenantID string) (string, error)

	// RevokeKey 吊销租户密钥
	// 将密钥标记为 revoked，禁止使用
	// 参数:
	//   ctx: 上下文对象
	//   tenantID: 租户标识符
	//   keyID: 密钥标识符
	//   reason: 吊销原因
	// 返回:
	//   error: 错误信息
	RevokeKey(
		ctx context.Context,
		tenantID string,
		keyID string,
		reason string,
	) error

	// ValidateJWTHeader 验证 JWT Header
	// 检查 alg、typ、kid 等字段的合法性
	// 参数:
	//   header: JWT Header
	// 返回:
	//   valid: 是否有效
	//   error: 错误信息
	ValidateJWTHeader(header map[string]interface{}) (bool, error)

	// ValidateStandardClaims 验证 JWT 标准声明
	// 检查 exp、nbf、iat 等标准字段
	// 参数:
	//   claims: JWT Claims
	//   clockSkew: 允许的时钟偏差（秒）
	// 返回:
	//   valid: 是否有效
	//   error: 错误信息
	ValidateStandardClaims(
		claims jwt.MapClaims,
		clockSkew int64,
	) (bool, error)

	// ExtractKeyID 从 JWT 中提取密钥标识符
	// 解析 JWT Header 中的 kid 字段
	// 参数:
	//   tokenString: JWT 字符串
	// 返回:
	//   keyID: 密钥标识符
	//   error: 错误信息
	ExtractKeyID(tokenString string) (string, error)

	// EncryptSensitiveData 加密敏感数据
	// 使用 AES-256-GCM 加密敏感数据（如 Refresh Token）
	// 参数:
	//   plaintext: 明文数据
	//   tenantID: 租户标识符（用于获取数据加密密钥）
	// 返回:
	//   ciphertext: 密文数据（Base64 编码）
	//   error: 错误信息
	EncryptSensitiveData(
		plaintext string,
		tenantID string,
	) (string, error)

	// DecryptSensitiveData 解密敏感数据
	// 使用 AES-256-GCM 解密敏感数据
	// 参数:
	//   ciphertext: 密文数据（Base64 编码）
	//   tenantID: 租户标识符
	// 返回:
	//   plaintext: 明文数据
	//   error: 错误信息
	DecryptSensitiveData(
		ciphertext string,
		tenantID string,
	) (string, error)
}

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
