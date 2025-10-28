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

// KeyManager manages cryptographic keys. This is a simplified in-memory implementation for demonstration.
type KeyManager struct {
	logger logger.Logger

	// In-memory key store for simplicity
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	mu         sync.RWMutex
}

// NewKeyManager creates a new key manager instance.
func NewKeyManager(log logger.Logger) (*KeyManager, error) {
	// Generate a single RSA key pair for the entire application lifecycle.
	// In a real application, this would be loaded from a secure store like Vault.
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

// GenerateJWT generates a new JWT signed with the in-memory private key.
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

// VerifyJWT verifies a JWT using the in-memory public key.
func (km *KeyManager) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New(errors.ErrCodeUnauthorized, "unexpected signing method: %v", token.Header["alg"])
		}
		// In a real multi-key system, you'd use the 'kid' from the token header
		// to look up the correct public key here.
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

// EncryptSensitiveData encrypts data using RSA-OAEP.
func (km *KeyManager) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	// Using the public key for encryption
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, km.publicKey, data, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to encrypt data")
	}
	return encryptedBytes, nil
}

// DecryptSensitiveData decrypts data using RSA-OAEP.
func (km *KeyManager) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	// Using the private key for decryption
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, km.privateKey, data, nil)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to decrypt data")
	}
	return decryptedBytes, nil
}

// --- Simplified/Placeholder implementations for other KeyManager methods ---

func (km *KeyManager) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.privateKey, km.keyID, nil
}

func (km *KeyManager) GetPublicKey(ctx context.Context, tenantID string, keyID string) (*rsa.PublicKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if keyID != km.keyID {
		return nil, errors.New(errors.CodeNotFound, "public key not found for kid: %s", keyID)
	}
	return km.publicKey, nil
}

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
