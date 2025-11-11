package crypto

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// KeyStatus identifies the lifecycle status of a cryptographic key.
// KeyStatus 标识加密密钥的生命周期状态。
type KeyStatus int

const (
	// KeyStatusUnknown represents an unknown or uninitialized key status.
	// KeyStatusUnknown 表示未知或未初始化的密钥状态。
	KeyStatusUnknown KeyStatus = iota
	// KeyStatusActive indicates the key is active and can be used for signing.
	// KeyStatusActive 表示密钥处于活动状态，可用于签名。
	KeyStatusActive
	// KeyStatusInactive indicates the key is inactive and should only be used for verification.
	// KeyStatusInactive 表示密钥处于非活动状态，只应用于验证。
	KeyStatusInactive
)

// Algorithm constants for key types.
// 密钥类型的算法常量。
const (
	// RSA2048 represents the RSA algorithm with a 2048-bit key.
	// RSA2048 代表使用 2048 位密钥的 RSA 算法。
	RSA2048 = "RSA-2048"
)

// KeyMetadata holds descriptive information about a cryptographic key.
// KeyMetadata 包含有关加密密钥的描述性信息。
type KeyMetadata struct {
	ID        string
	Algorithm string
	Status    KeyStatus
	CreatedAt time.Time
}

// KeyPair holds the raw public and private key material along with its metadata.
// KeyPair 包含原始的公钥和私钥材料及其元数据。
type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
	Meta       KeyMetadata
}

// JWTManager is a legacy interface provided for backward compatibility with existing middleware and tests.
// It defines the core operations of generating and verifying JWTs.
// JWTManager 是为与现有中间件和测试向后兼容而提供的旧版接口。
// 它定义了生成和验证 JWT 的核心操作。
type JWTManager interface {
	// GenerateJWT creates and signs a new JWT for a given tenant with the specified claims.
	// GenerateJWT 为给定租户使用指定的声明创建并签署一个新的 JWT。
	GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error)
	// VerifyJWT parses and validates a JWT string for a given tenant.
	// VerifyJWT 为给定租户解析并验证 JWT 字符串。
	VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error)
}
