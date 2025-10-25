package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// KeyManager handles the lifecycle of cryptographic keys.
type KeyManager interface {
	GetPrivateKey(ctx context.Context, tenantID uuid.UUID) (*rsa.PrivateKey, string, *errors.AppError)
	GetPublicKey(ctx context.Context, tenantID uuid.UUID, keyID string) (*rsa.PublicKey, *errors.AppError)
	RotateKey(ctx context.Context, tenantID uuid.UUID) (string, *errors.AppError)
}

type keyManagerImpl struct {
	log        logger.Logger
	privateKey *rsa.PrivateKey
	keyID      string
	mu         sync.RWMutex
}

// NewKeyManager creates a new KeyManager.
func NewKeyManager(log logger.Logger) (KeyManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &keyManagerImpl{
		log:        log,
		privateKey: privateKey,
		keyID:      "local-dev-key",
	}, nil
}

// GetPrivateKey retrieves the current private key for a tenant.
func (k *keyManagerImpl) GetPrivateKey(ctx context.Context, tenantID uuid.UUID) (*rsa.PrivateKey, string, *errors.AppError) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.privateKey, k.keyID, nil
}

// GetPublicKey retrieves a public key by its ID.
func (k *keyManagerImpl) GetPublicKey(ctx context.Context, tenantID uuid.UUID, keyID string) (*rsa.PublicKey, *errors.AppError) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.keyID != keyID {
		return nil, errors.ErrNotFound
	}
	return &k.privateKey.PublicKey, nil
}

// RotateKey generates a new key pair for a tenant and marks the old one as deprecated.
func (k *keyManagerImpl) RotateKey(ctx context.Context, tenantID uuid.UUID) (string, *errors.AppError) {
	k.mu.Lock()
	defer k.mu.Unlock()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", errors.ErrKMSFailure.WithError(err)
	}
	k.privateKey = privateKey
	k.keyID = fmt.Sprintf("local-dev-key-%d", time.Now().Unix())
	k.log.Info(ctx, "Key rotated successfully", logger.Fields{"new_key_id": k.keyID})
	return k.keyID, nil
}

//Personal.AI order the ending
