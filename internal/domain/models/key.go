package models

import (
	"crypto/rsa"
	"time"
)

// Key represents the metadata of a cryptographic key used for signing tokens.
// It stores information about the key's identity, location, and lifecycle status.
// Key 代表用于签署令牌的加密密钥的元数据。
// 它存储有关密钥身份、位置和生命周期状态的信息。
type Key struct {
	// ID is the unique identifier for the key, often referred to as the Key ID (kid).
	// ID 是密钥的唯一标识符，通常称为密钥 ID (kid)。
	ID string `gorm:"primaryKey"`
	// TenantID is the identifier of the tenant that owns this key.
	// TenantID 是拥有此密钥的租户的标识符。
	TenantID string
	// ProviderType indicates the type of key provider (e.g., "vault", "pkcs11").
	// ProviderType 指示密钥提供程序的类型（例如，“vault”、“pkcs11”）。
	ProviderType string
	// ProviderRef is a reference or path to the key within the provider's system.
	// ProviderRef 是提供程序系统中密钥的引用或路径。
	ProviderRef string
	// PublicKey is the parsed public key object, ignored by GORM.
	// PublicKey 是已解析的公钥对象，GORM 会忽略它。
	PublicKey *rsa.PublicKey `gorm:"-"`
	// PublicKeyPEM is the public key in PEM format.
	// PublicKeyPEM 是 PEM 格式的公钥。
	PublicKeyPEM string
	// Status indicates the current lifecycle status of the key (e.g., "active", "deprecated", "revoked").
	// Status 指示密钥的当前生命周期状态（例如，“活动”、“已弃用”、“已撤销”）。
	Status string
	// CompromisedAt is the timestamp when the key was marked as compromised. Null if not compromised.
	// CompromisedAt 是密钥被标记为已泄露的时间戳。如果未泄露，则为 Null。
	CompromisedAt *time.Time
	// CreatedAt is the timestamp when the key record was created.
	// CreatedAt 是创建密钥记录的时间戳。
	CreatedAt time.Time
	// UpdatedAt is the timestamp when the key record was last updated.
	// UpdatedAt 是密钥记录上次更新的时间戳。
	UpdatedAt time.Time
}

// KeySpec defines the specifications for generating a new cryptographic key.
// It allows requesting keys with specific algorithms and sizes.
// KeySpec 定义了生成新加密密钥的规范。
// 它允许请求具有特定算法和大小的密钥。
type KeySpec struct {
	// Algorithm is the cryptographic algorithm to use (e.g., "RSA", "ECDSA").
	// Algorithm 是要使用的加密算法（例如，“RSA”、“ECDSA”）。
	Algorithm string
	// Bits is the key size in bits (e.g., 2048 for RSA).
	// Bits 是密钥大小（以位为单位）（例如，RSA 为 2048）。
	Bits int
}
