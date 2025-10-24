package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/pkg/constants"
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
	vaultClient VaultClient
	cache       redis.CacheManager
	log         logger.Logger
	localCache  sync.Map // In-memory cache for hot keys
}

// NewKeyManager creates a new KeyManager.
func NewKeyManager(vaultClient VaultClient, cache redis.CacheManager, log logger.Logger) KeyManager {
	return &keyManagerImpl{
		vaultClient: vaultClient,
		cache:       cache,
		log:         log,
	}
}

// GetPrivateKey retrieves the current private key for a tenant.
func (k *keyManagerImpl) GetPrivateKey(ctx context.Context, tenantID uuid.UUID) (*rsa.PrivateKey, string, *errors.AppError) {
	// A real implementation would get the active key ID from the tenant model.
	activeKeyID := "" // Placeholder
	keyPath := k.getTenantKeyPath(tenantID, activeKeyID)

	// Check local cache first
	if keyData, found := k.localCache.Load(keyPath); found {
		cachedKey := keyData.(rsa.PrivateKey)
		return &cachedKey, activeKeyID, nil
	}

	// A real implementation would check Redis cache next.

	// Fetch from Vault
	secret, err := k.vaultClient.GetKey(ctx, keyPath)
	if err != nil {
		return nil, "", err
	}

	// A real implementation would parse the PEM data from the secret.
	privateKey := &rsa.PrivateKey{} // Placeholder

	k.localCache.Store(keyPath, *privateKey)

	return privateKey, activeKeyID, nil
}

// GetPublicKey retrieves a public key by its ID.
func (k *keyManagerImpl) GetPublicKey(ctx context.Context, tenantID uuid.UUID, keyID string) (*rsa.PublicKey, *errors.AppError) {
	// Similar caching logic as GetPrivateKey would be implemented here.
	keyPath := k.getTenantKeyPath(tenantID, keyID)
	secret, err := k.vaultClient.GetKey(ctx, keyPath)
	if err != nil {
		return nil, err
	}

	// A real implementation would parse the PEM data from the secret.
	publicKey := &rsa.PublicKey{} // Placeholder

	return publicKey, nil
}

// RotateKey generates a new key pair for a tenant and marks the old one as deprecated.
func (k *keyManagerImpl) RotateKey(ctx context.Context, tenantID uuid.UUID) (string, *errors.AppError) {
	newKeyID := fmt.Sprintf("%s-%d", tenantID.String(), time.Now().Unix())

	// Generate new key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", errors.ErrKMSFailure.WithError(err)
	}

	// A real implementation would convert keys to PEM format.
	keyData := map[string]interface{}{
		"private_key": "PEM_PRIVATE_KEY",
		"public_key":  "PEM_PUBLIC_KEY",
		"status":      "active",
		"algorithm":   constants.RS256,
	}

	// Save to Vault
	keyPath := k.getTenantKeyPath(tenantID, newKeyID)
	if appErr := k.vaultClient.SaveKey(ctx, keyPath, keyData); appErr != nil {
		return "", appErr
	}

	// A real implementation would update the old key's status to "deprecated"
	// and update the tenant's active key ID in the database.

	k.log.Info(ctx, "Key rotated successfully", logger.Fields{"tenant_id": tenantID, "new_key_id": newKeyID})
	return newKeyID, nil
}

func (k *keyManagerImpl) getTenantKeyPath(tenantID uuid.UUID, keyID string) string {
	return fmt.Sprintf("tenants/%s/keys/%s", tenantID.String(), keyID)
}
//Personal.AI order the ending