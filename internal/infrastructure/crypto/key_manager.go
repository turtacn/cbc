// Package crypto provides key management services including generation, rotation,
// caching, and multi-tenant key isolation using Vault and Redis.
package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// KeyAlgorithm represents the cryptographic algorithm type.
type KeyAlgorithm string

const (
	// RSA2048 represents 2048-bit RSA algorithm
	RSA2048 KeyAlgorithm = "RSA-2048"
	// RSA4096 represents 4096-bit RSA algorithm
	RSA4096 KeyAlgorithm = "RSA-4096"
	// ECDSAP256 represents ECDSA with P-256 curve
	ECDSAP256 KeyAlgorithm = "ECDSA-P256"
	// ECDSAP384 represents ECDSA with P-384 curve
	ECDSAP384 KeyAlgorithm = "ECDSA-P384"
)

// KeyStatus represents the lifecycle status of a key.
type KeyStatus string

const (
	// KeyStatusActive indicates the key is currently active
	KeyStatusActive KeyStatus = "active"
	// KeyStatusDeprecated indicates the key is deprecated but still valid
	KeyStatusDeprecated KeyStatus = "deprecated"
	// KeyStatusExpired indicates the key has expired
	KeyStatusExpired KeyStatus = "expired"
)

// KeyPair represents a public/private key pair.
type KeyPair struct {
	// ID is the unique identifier for this key pair
	ID string
	// TenantID identifies the tenant this key belongs to
	TenantID string
	// Algorithm specifies the cryptographic algorithm
	Algorithm KeyAlgorithm
	// PrivateKey in PEM format
	PrivateKey string
	// PublicKey in PEM format
	PublicKey string
	// Status indicates the key lifecycle status
	Status KeyStatus
	// CreatedAt is when the key was created
	CreatedAt time.Time
	// ExpiresAt is when the key expires
	ExpiresAt time.Time
	// RotatedAt is when the key was rotated (deprecated)
	RotatedAt *time.Time
}

// KeyMetadata contains key metadata without sensitive data.
type KeyMetadata struct {
	ID        string
	TenantID  string
	Algorithm KeyAlgorithm
	Status    KeyStatus
	CreatedAt time.Time
	ExpiresAt time.Time
}

// KeyManagementService defines the interface for key management operations.
type KeyManagementService interface {
	GetActiveKeyForTenant(ctx context.Context, tenantID string) (*KeyPair, error)
	GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error)
	ListTenantKeys(ctx context.Context, tenantID string) ([]*KeyMetadata, error)
}

// KeyManager manages cryptographic keys with caching and rotation.
type KeyManager struct {
	vaultClient  *VaultClient
	cacheManager *redis.CacheManager
	logger       logger.Logger
	config       *KeyManagerConfig

	// Memory cache for hot keys
	keyCache      *lru.Cache[string, *KeyPair]
	cacheMutex    sync.RWMutex
	metadataCache *lru.Cache[string, *KeyMetadata]
}

// KeyManagerConfig holds key manager configuration.
type KeyManagerConfig struct {
	// VaultPath is the base path in Vault for key storage
	VaultPath string
	// CacheSize is the maximum number of keys to cache in memory
	CacheSize int
	// CacheTTL is the time-to-live for cached keys
	CacheTTL time.Duration
	// GracePeriod is the duration deprecated keys remain valid
	GracePeriod time.Duration
	// DefaultAlgorithm is the algorithm used for new keys
	DefaultAlgorithm KeyAlgorithm
	// KeyValidityPeriod is how long new keys are valid
	KeyValidityPeriod time.Duration
}

// DefaultKeyManagerConfig returns default configuration.
func DefaultKeyManagerConfig() *KeyManagerConfig {
	return &KeyManagerConfig{
		VaultPath:         "secret/data/keys",
		CacheSize:         1000,
		CacheTTL:          time.Hour,
		GracePeriod:       24 * time.Hour,
		DefaultAlgorithm:  RSA2048,
		KeyValidityPeriod: 90 * 24 * time.Hour, // 90 days
	}
}

// NewKeyManager creates a new key manager instance.
//
// Parameters:
//   - vaultClient: Vault client for key storage
//   - cacheManager: Redis cache manager
//   - config: Key manager configuration
//   - log: Logger instance
//
// Returns:
//   - *KeyManager: Initialized key manager
//   - error: Initialization error if any
func NewKeyManager(
	vaultClient *VaultClient,
	cacheManager *redis.CacheManager,
	config *KeyManagerConfig,
	log logger.Logger,
) (*KeyManager, error) {
	if vaultClient == nil {
		return nil, errors.New(errors.CodeInvalidArgument, "vault client is required")
	}

	if config == nil {
		config = DefaultKeyManagerConfig()
	}

	// Initialize LRU cache for keys
	keyCache, err := lru.New[string, *KeyPair](config.CacheSize)
if err != nil {
return nil, errors.Wrap(err, errors.CodeInternal, "failed to create key cache")
}

// Initialize LRU cache for metadata
metadataCache, err := lru.New[string, *KeyMetadata](config.CacheSize * 2)
if err != nil {
return nil, errors.Wrap(err, errors.CodeInternal, "failed to create metadata cache")
}

km := &KeyManager{
vaultClient:   vaultClient,
cacheManager:  cacheManager,
logger:        log,
config:        config,
keyCache:      keyCache,
metadataCache: metadataCache,
}

log.Info(context.Background(), "Key manager initialized",
	logger.Int("cache_size", config.CacheSize),
	logger.Duration("cache_ttl", config.CacheTTL),
	logger.Duration("grace_period", config.GracePeriod),
)

return km, nil
}

// GenerateKeyPair generates a new key pair for a tenant.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//   - algorithm: Cryptographic algorithm to use
//
// Returns:
//   - *KeyPair: Generated key pair
//   - error: Generation error if any
func (km *KeyManager) GenerateKeyPair(ctx context.Context, tenantID string, algorithm KeyAlgorithm) (*KeyPair, error) {
	if tenantID == "" {
		return nil, errors.New(errors.CodeInvalidArgument, "tenant ID is required")
	}

	// Generate unique key ID
	keyID := fmt.Sprintf("%s-%d", tenantID, time.Now().Unix())

	var privateKeyPEM, publicKeyPEM string
	var err error

	// Generate key pair based on algorithm
	switch algorithm {
	case RSA2048:
		privateKeyPEM, publicKeyPEM, err = km.generateRSAKeyPair(2048)
	case RSA4096:
		privateKeyPEM, publicKeyPEM, err = km.generateRSAKeyPair(4096)
	case ECDSAP256:
		privateKeyPEM, publicKeyPEM, err = km.generateECDSAKeyPair(elliptic.P256())
	case ECDSAP384:
		privateKeyPEM, publicKeyPEM, err = km.generateECDSAKeyPair(elliptic.P384())
	default:
		return nil, errors.New(errors.CodeInvalidArgument, "unsupported algorithm: %s", algorithm)
	}

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to generate key pair")
	}

	// Create key pair object
	now := time.Now()
	keyPair := &KeyPair{
		ID:         keyID,
		TenantID:   tenantID,
		Algorithm:  algorithm,
		PrivateKey: privateKeyPEM,
		PublicKey:  publicKeyPEM,
		Status:     KeyStatusActive,
		CreatedAt:  now,
		ExpiresAt:  now.Add(km.config.KeyValidityPeriod),
	}

	// Store in Vault
	if err := km.storeKeyPairInVault(ctx, keyPair); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to store key pair")
	}

	// Cache the key pair
	km.cacheKeyPair(keyPair)

	// Index by tenant for quick lookup
	if err := km.indexKeyByTenant(ctx, tenantID, keyID); err != nil {
		km.logger.Warn(ctx, "Failed to index key by tenant",
			logger.String("tenant_id", tenantID),
			logger.String("key_id", keyID),
			logger.Error(err),
		)
	}

	km.logger.Info(ctx, "Key pair generated",
		logger.String("key_id", keyID),
		logger.String("tenant_id", tenantID),
		logger.String("algorithm", string(algorithm)),
	)

	return keyPair, nil
}

// generateRSAKeyPair generates an RSA key pair.
func (km *KeyManager) generateRSAKeyPair(bits int) (privateKeyPEM, publicKeyPEM string, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Encode private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEM = string(pem.EncodeToMemory(privateKeyBlock))

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEM = string(pem.EncodeToMemory(publicKeyBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

// generateECDSAKeyPair generates an ECDSA key pair.
func (km *KeyManager) generateECDSAKeyPair(curve elliptic.Curve) (privateKeyPEM, publicKeyPEM string, err error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Encode private key to PEM
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEM = string(pem.EncodeToMemory(privateKeyBlock))

	// Encode public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEM = string(pem.EncodeToMemory(publicKeyBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

// GetPrivateKey retrieves a private key by ID.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keyID: Key identifier
//
// Returns:
//   - string: Private key in PEM format
//   - error: Retrieval error if any
func (km *KeyManager) GetPrivateKey(ctx context.Context, keyID string) (string, error) {
	// Check memory cache first
	if keyPair := km.getKeyPairFromCache(keyID); keyPair != nil {
		return keyPair.PrivateKey, nil
	}

	// Load from Vault
	keyPair, err := km.loadKeyPairFromVault(ctx, keyID)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeNotFound, "failed to load private key")
	}

	// Cache for future use
	km.cacheKeyPair(keyPair)

	return keyPair.PrivateKey, nil
}

// GetPublicKey retrieves a public key by ID.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keyID: Key identifier
//
// Returns:
//   - string: Public key in PEM format
//   - error: Retrieval error if any
func (km *KeyManager) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	// Check memory cache first
	if keyPair := km.getKeyPairFromCache(keyID); keyPair != nil {
		return keyPair.PublicKey, nil
	}

	// Load from Vault
	keyPair, err := km.loadKeyPairFromVault(ctx, keyID)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeNotFound, "failed to load public key")
	}

	// Cache for future use
	km.cacheKeyPair(keyPair)

	return keyPair.PublicKey, nil
}

// GetKeyPair retrieves a complete key pair by ID.
//
// Parameters:
//   - ctx: Context for timeout control
//   - keyID: Key identifier
//
// Returns:
//   - *KeyPair: Key pair
//   - error: Retrieval error if any
func (km *KeyManager) GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error) {
	// Check memory cache first
	if keyPair := km.getKeyPairFromCache(keyID); keyPair != nil {
		return keyPair, nil
	}

	// Load from Vault
	keyPair, err := km.loadKeyPairFromVault(ctx, keyID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "failed to load key pair")
	}

	// Cache for future use
	km.cacheKeyPair(keyPair)

	return keyPair, nil
}

// GetActiveKeyForTenant retrieves the active key for a tenant.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//
// Returns:
//   - *KeyPair: Active key pair
//   - error: Retrieval error if any
func (km *KeyManager) GetActiveKeyForTenant(ctx context.Context, tenantID string) (*KeyPair, error) {
	// Get tenant's key IDs from index
	keyIDs, err := km.getTenantKeyIDs(ctx, tenantID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "failed to get tenant keys")
	}

	if len(keyIDs) == 0 {
		return nil, errors.New(errors.CodeNotFound, "no keys found for tenant: %s", tenantID)
	}

	// Find active key
	for _, keyID := range keyIDs {
		keyPair, err := km.GetKeyPair(ctx, keyID)
		if err != nil {
			km.logger.Warn(ctx, "Failed to load key",
				logger.String("key_id", keyID),
				logger.Error(err),
			)
			continue
		}

		if keyPair.Status == KeyStatusActive && time.Now().Before(keyPair.ExpiresAt) {
			return keyPair, nil
		}
	}

	return nil, errors.New(errors.CodeNotFound, "no active key found for tenant: %s", tenantID)
}

// RotateKey rotates a key by generating a new one and deprecating the old one.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//   - oldKeyID: ID of the key to rotate
//
// Returns:
//   - *KeyPair: New key pair
//   - error: Rotation error if any
func (km *KeyManager) RotateKey(ctx context.Context, tenantID string, oldKeyID string) (*KeyPair, error) {
	// Load old key
	oldKey, err := km.GetKeyPair(ctx, oldKeyID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeNotFound, "failed to load old key")
	}

	if oldKey.TenantID != tenantID {
		return nil, errors.New(errors.CodePermissionDenied, "key does not belong to tenant", nil)
	}

	// Generate new key with same algorithm
	newKey, err := km.GenerateKeyPair(ctx, tenantID, oldKey.Algorithm)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to generate new key")
	}

	// Deprecate old key
	now := time.Now()
	oldKey.Status = KeyStatusDeprecated
	oldKey.RotatedAt = &now
	oldKey.ExpiresAt = now.Add(km.config.GracePeriod)

	// Update old key in Vault
	if err := km.storeKeyPairInVault(ctx, oldKey); err != nil {
		km.logger.Error(ctx, "Failed to update deprecated key", err,
			logger.String("key_id", oldKeyID),
		)
	}

	// Update cache
	km.cacheKeyPair(oldKey)

	km.logger.Info(ctx, "Key rotated",
		logger.String("old_key_id", oldKeyID),
		logger.String("new_key_id", newKey.ID),
		logger.String("tenant_id", tenantID),
		logger.Duration("grace_period", km.config.GracePeriod),
	)

	return newKey, nil
}

// ListTenantKeys lists all keys for a tenant.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//
// Returns:
//   - []*KeyMetadata: List of key metadata
//   - error: List error if any
func (km *KeyManager) ListTenantKeys(ctx context.Context, tenantID string) ([]*KeyMetadata, error) {
	keyIDs, err := km.getTenantKeyIDs(ctx, tenantID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get tenant keys")
	}

	metadata := make([]*KeyMetadata, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		keyPair, err := km.GetKeyPair(ctx, keyID)
		if err != nil {
			km.logger.Warn(ctx, "Failed to load key metadata",
				logger.String("key_id", keyID),
				logger.Error(err),
			)
			continue
		}

		metadata = append(metadata, &KeyMetadata{
			ID:        keyPair.ID,
			TenantID:  keyPair.TenantID,
			Algorithm: keyPair.Algorithm,
			Status:    keyPair.Status,
			CreatedAt: keyPair.CreatedAt,
			ExpiresAt: keyPair.ExpiresAt,
		})
	}

	return metadata, nil
}

// CleanupExpiredKeys removes expired keys from storage.
//
// Parameters:
//   - ctx: Context for timeout control
//
// Returns:
//   - int: Number of keys cleaned up
//   - error: Cleanup error if any
func (km *KeyManager) CleanupExpiredKeys(ctx context.Context) (int, error) {
	// This is a simplified implementation
	// In production, you would iterate through all keys
	count := 0

	km.logger.Info(ctx, "Starting expired key cleanup")

	// Implementation would scan Vault and remove expired keys
	// For now, just log the operation
	km.logger.Info(ctx, "Expired key cleanup completed", logger.Int("count", count))

	return count, nil
}

// storeKeyPairInVault stores a key pair in Vault.
func (km *KeyManager) storeKeyPairInVault(ctx context.Context, keyPair *KeyPair) error {
	path := fmt.Sprintf("%s/%s", km.config.VaultPath, keyPair.ID)

	data := SecretData{
		"id":          keyPair.ID,
		"tenant_id":   keyPair.TenantID,
		"algorithm":   string(keyPair.Algorithm),
		"private_key": keyPair.PrivateKey,
		"public_key":  keyPair.PublicKey,
		"status":      string(keyPair.Status),
		"created_at":  keyPair.CreatedAt.Format(time.RFC3339),
		"expires_at":  keyPair.ExpiresAt.Format(time.RFC3339),
	}

	if keyPair.RotatedAt != nil {
		data["rotated_at"] = keyPair.RotatedAt.Format(time.RFC3339)
	}

	return km.vaultClient.WriteSecret(ctx, path, data)
}

// loadKeyPairFromVault loads a key pair from Vault.
func (km *KeyManager) loadKeyPairFromVault(ctx context.Context, keyID string) (*KeyPair, error) {
	path := fmt.Sprintf("%s/%s", km.config.VaultPath, keyID)

	data, err := km.vaultClient.ReadSecret(ctx, path)
	if err != nil {
		return nil, err
	}

	keyPair := &KeyPair{}

	if id, ok := data["id"].(string); ok {
		keyPair.ID = id
	}
	if tenantID, ok := data["tenant_id"].(string); ok {
		keyPair.TenantID = tenantID
	}
	if algorithm, ok := data["algorithm"].(string); ok {
		keyPair.Algorithm = KeyAlgorithm(algorithm)
	}
	if privateKey, ok := data["private_key"].(string); ok {
		keyPair.PrivateKey = privateKey
	}
	if publicKey, ok := data["public_key"].(string); ok {
		keyPair.PublicKey = publicKey
	}
	if status, ok := data["status"].(string); ok {
		keyPair.Status = KeyStatus(status)
	}
	if createdAt, ok := data["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			keyPair.CreatedAt = t
		}
	}
	if expiresAt, ok := data["expires_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			keyPair.ExpiresAt = t
		}
	}
	if rotatedAt, ok := data["rotated_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, rotatedAt); err == nil {
			keyPair.RotatedAt = &t
		}
	}

	return keyPair, nil
}

// cacheKeyPair caches a key pair in memory.
func (km *KeyManager) cacheKeyPair(keyPair *KeyPair) {
	km.cacheMutex.Lock()
	defer km.cacheMutex.Unlock()

	km.keyCache.Add(keyPair.ID, keyPair)

	// Also cache metadata
	metadata := &KeyMetadata{
		ID:        keyPair.ID,
		TenantID:  keyPair.TenantID,
		Algorithm: keyPair.Algorithm,
		Status:    keyPair.Status,
		CreatedAt: keyPair.CreatedAt,
		ExpiresAt: keyPair.ExpiresAt,
	}
	km.metadataCache.Add(keyPair.ID, metadata)

	// Cache in Redis if available
	if km.cacheManager != nil {
		cacheKey := fmt.Sprintf("key:%s", keyPair.ID)
		data, _ := json.Marshal(keyPair)
		_ = km.cacheManager.Set(context.Background(), cacheKey, string(data), &redis.CacheOptions{TTL: km.config.CacheTTL})
	}
}

// getKeyPairFromCache retrieves a key pair from cache.
func (km *KeyManager) getKeyPairFromCache(keyID string) *KeyPair {
	km.cacheMutex.RLock()
	defer km.cacheMutex.RUnlock()

	// Check memory cache
	if keyPair, ok := km.keyCache.Get(keyID); ok {
		return keyPair
	}

	// Check Redis cache if available
	if km.cacheManager != nil {
		cacheKey := fmt.Sprintf("key:%s", keyID)
		var keyPair KeyPair
		if ok, err := km.cacheManager.Get(context.Background(), cacheKey, &keyPair, nil); err == nil && ok {
			// Update memory cache
			km.keyCache.Add(keyID, &keyPair)
			return &keyPair
		}
	}

	return nil
}

// indexKeyByTenant indexes a key ID by tenant for quick lookup.
func (km *KeyManager) indexKeyByTenant(ctx context.Context, tenantID, keyID string) error {
	if km.cacheManager == nil {
		return nil
	}

	indexKey := fmt.Sprintf("tenant-keys:%s", tenantID)

	// Get existing key IDs
	keyIDs, _ := km.getTenantKeyIDs(ctx, tenantID)

	// Add new key ID
	keyIDs = append(keyIDs, keyID)

	// Store updated list
	data, err := json.Marshal(keyIDs)
	if err != nil {
		return err
	}

	return km.cacheManager.Set(ctx, indexKey, string(data), nil) // No expiration for index
}

// getTenantKeyIDs retrieves all key IDs for a tenant.
func (km *KeyManager) getTenantKeyIDs(ctx context.Context, tenantID string) ([]string, error) {
	if km.cacheManager == nil {
		return []string{}, nil
	}

	indexKey := fmt.Sprintf("tenant-keys:%s", tenantID)

	var data string
	ok, err := km.cacheManager.Get(ctx, indexKey, &data, nil)
	if err != nil || !ok {
		return []string{}, nil
	}

	var keyIDs []string
	if err := json.Unmarshal([]byte(data), &keyIDs); err != nil {
		return []string{}, err
	}

	return keyIDs, nil
}

// InvalidateCache invalidates cached keys.
//
// Parameters:
//   - keyID: Key ID to invalidate (empty for all keys)
func (km *KeyManager) InvalidateCache(keyID string) {
	km.cacheMutex.Lock()
	defer km.cacheMutex.Unlock()

	if keyID != "" {
		km.keyCache.Remove(keyID)
		km.metadataCache.Remove(keyID)

		if km.cacheManager != nil {
			cacheKey := fmt.Sprintf("key:%s", keyID)
			_ = km.cacheManager.Delete(context.Background(), cacheKey, nil)
		}
	} else {
		km.keyCache.Purge()
		km.metadataCache.Purge()
	}

	km.logger.Debug(context.Background(), "Cache invalidated", logger.String("key_id", keyID))
}

// Close closes the key manager and releases resources.
func (km *KeyManager) Close() error {
	km.InvalidateCache("")
	km.logger.Info(context.Background(), "Key manager closed")
	return nil
}

//Personal.AI order the ending

