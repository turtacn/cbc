// Package crypto provides key management services including generation, rotation,
// caching, and multi-tenant key isolation using Vault and Redis.
package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// KeyManager provides a simplified, in-memory key management solution for demonstration and testing.
// In a production environment, this would be replaced by a robust solution interacting with a secure key store like HashiCorp Vault.
// KeyManager 提供一个简化的内存密钥管理解决方案，用于演示和测试。
// 在生产环境中，这将由一个与安全密钥库（如 HashiCorp Vault）交互的强大解决方案所取代。
type KeyManager struct {
	logger     logger.Logger
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	mu         sync.RWMutex
}

// NewKeyManager creates a new in-memory key manager instance.
// It generates a single static RSA key pair upon initialization.
// NewKeyManager 创建一个新的内存密钥管理器实例。
// 它在初始化时生成一个单一的静态 RSA 密钥对。
func NewKeyManager(log logger.Logger) (*KeyManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to generate RSA key")
	}

	km := &KeyManager{
		logger:     log,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      "test-kid-123",
	}

	log.Info(context.Background(), "In-memory Key manager initialized with a static RSA key")
	return km, nil
}

// GenerateJWT creates and signs a new JWT using the static in-memory private key.
// GenerateJWT 使用静态的内存私钥创建并签署一个新的 JWT。
func (km *KeyManager) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = km.keyID

	signedString, err := token.SignedString(km.privateKey)
	if err != nil {
		km.logger.Error(ctx, "Failed to sign JWT", err)
		return "", "", errors.Wrap(err, errors.CodeInternal, "failed to sign token")
	}
	return signedString, km.keyID, nil
}

// VerifyJWT parses and verifies a JWT using the static in-memory public key.
// VerifyJWT 使用静态的内存公钥解析和验证 JWT。
func (km *KeyManager) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New(errors.ErrCodeUnauthorized, "unexpected signing method: %v", token.Header["alg"])
		}
		return km.publicKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeUnauthorized, "JWT parsing failed")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New(errors.ErrCodeUnauthorized, "invalid JWT")
}

// EncryptSensitiveData encrypts a byte slice using the in-memory public key with RSA-OAEP.
// EncryptSensitiveData 使用内存中的公钥和 RSA-OAEP 加密字节切片。
func (km *KeyManager) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, km.publicKey, data, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt data")
	}
	return encryptedBytes, nil
}

// DecryptSensitiveData decrypts a byte slice using the in-memory private key with RSA-OAEP.
// DecryptSensitiveData 使用内存中的私钥和 RSA-OAEP 解密字节切片。
func (km *KeyManager) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, km.privateKey, data, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt data")
	}
	return decryptedBytes, nil
}

// GetPrivateKey is a simplified method to get the raw private key.
// In a real system, this would not exist; operations would be performed within the key manager.
// GetPrivateKey 是获取原始私钥的简化方法。
// 在真实系统中，这将不存在；操作将在密钥管理器内部执行。
func (km *KeyManager) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey, km.keyID, nil
}

// GetPublicKey is a simplified method to get the raw public key.
// GetPublicKey 是获取原始公钥的简化方法。
func (km *KeyManager) GetPublicKey(ctx context.Context, tenantID string, keyID string) (*rsa.PublicKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if keyID != km.keyID {
		return nil, errors.New(errors.CodeNotFound, "public key not found for kid: %s", keyID)
	}
	return km.publicKey, nil
}

// RotateKey simulates key rotation by generating a new in-memory key pair.
// RotateKey 通过生成新的内存密钥对来模拟密钥轮换。
func (km *KeyManager) RotateKey(ctx context.Context, tenantID string) (string, error) {
	km.mu.Lock()
	defer km.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to generate new RSA key for rotation")
	}
	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey
	km.keyID = "test-kid-" + time.Now().Format("20060102150405") // new kid for rotated key
	km.logger.Info(ctx, "In-memory key rotated successfully", logger.String("new_kid", km.keyID))
	return km.keyID, nil
}
