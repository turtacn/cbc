// Package kms implements the KeyManagementService interface using HashiCorp Vault.
package kms

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
	"github.com/patrickmn/go-cache"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// VaultAdapter is a Vault-backed implementation of the KeyManagementService.
// It uses a multi-level cache (L1 in-memory, L2 Redis) for public keys
// and a short-lived L1 cache for private keys.
type VaultAdapter struct {
	vaultClient *vault.Client
	redisClient *redis.Client
	l1Cache     *cache.Cache
	logger      logger.Logger
	config      config.VaultConfig
}

// NewVaultAdapter creates a new VaultAdapter.
func NewVaultAdapter(cfg config.VaultConfig, vaultClient *vault.Client, redisClient *redis.Client, logger logger.Logger) (service.CryptoService, error) {
	return &VaultAdapter{
		vaultClient: vaultClient,
		redisClient: redisClient,
		l1Cache:     cache.New(1*time.Minute, 5*time.Minute), // Short TTL for private keys
		logger:      logger.WithComponent("VaultAdapter"),
		config:      cfg,
	}, nil
}

// GetPrivateKey retrieves the active private key for a tenant from Vault.
// It uses a short-lived in-memory cache to reduce latency.
func (a *VaultAdapter) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	cacheKey := fmt.Sprintf("privkey:%s", tenantID)
	if key, kid, found := a.getCachedPrivateKey(cacheKey); found {
		return key, kid, nil
	}

	// In a real implementation, you would look up the *active* key ID for the tenant.
	// For this phase, we'll assume a single key for simplicity.
	activeKeyID := "key-001"
	vaultPath := fmt.Sprintf("secret/data/cbc/tenants/%s/keys/%s", tenantID, activeKeyID)

	secret, err := a.vaultClient.Logical().Read(vaultPath)
	if err != nil {
		a.logger.Error(ctx, "failed to read private key from Vault", err, logger.String("tenant_id", tenantID))
		return nil, "", fmt.Errorf("could not retrieve private key from vault: %w", err)
	}
	if secret == nil || secret.Data["data"] == nil {
		return nil, "", fmt.Errorf("key not found in vault for tenant %s", tenantID)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, "", fmt.Errorf("invalid secret format in vault")
	}

	pemData, ok := data["private_key"].(string)
	if !ok {
		return nil, "", fmt.Errorf("private_key not found or not a string in vault secret")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemData))
	if err != nil {
		a.logger.Error(ctx, "failed to parse RSA private key from PEM", err, logger.String("tenant_id", tenantID))
		return nil, "", fmt.Errorf("could not parse private key: %w", err)
	}

	a.setCachedPrivateKey(cacheKey, privateKey, activeKeyID)
	return privateKey, activeKeyID, nil
}

// GetPublicKey retrieves a specific public key for a tenant by key ID.
// It uses a multi-level cache (L1 in-memory, L2 Redis) to reduce latency.
func (a *VaultAdapter) GetPublicKey(ctx context.Context, tenantID, keyID string) (*rsa.PublicKey, error) {
	// L1 Cache check
	l1CacheKey := fmt.Sprintf("pubkey:%s:%s", tenantID, keyID)
	if key, found := a.l1Cache.Get(l1CacheKey); found {
		if pubKey, ok := key.(*rsa.PublicKey); ok {
			return pubKey, nil
		}
	}

	// L2 Cache check
	l2CacheKey := fmt.Sprintf("pubkey:%s:%s", tenantID, keyID)
	val, err := a.redisClient.Get(ctx, l2CacheKey).Result()
	if err == nil {
		var pubKey rsa.PublicKey
		if err := json.Unmarshal([]byte(val), &pubKey); err == nil {
			a.l1Cache.Set(l1CacheKey, &pubKey, a.config.KeyCacheTTL)
			return &pubKey, nil
		}
	}

	// Fetch from Vault
	vaultPath := fmt.Sprintf("secret/data/cbc/tenants/%s/keys/%s", tenantID, keyID)
	secret, err := a.vaultClient.Logical().Read(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve public key from vault: %w", err)
	}
	if secret == nil || secret.Data["data"] == nil {
		return nil, fmt.Errorf("key not found in vault for tenant %s, key %s", tenantID, keyID)
	}

	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid secret format in vault")
	}

	pemData, ok := data["public_key"].(string)
	if !ok {
		return nil, fmt.Errorf("public_key not found or not a string in vault secret")
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemData))
	if err != nil {
		return nil, fmt.Errorf("could not parse public key: %w", err)
	}

	// Cache the public key
	a.l1Cache.Set(l1CacheKey, publicKey, a.config.KeyCacheTTL)
	jsonData, err := json.Marshal(publicKey)
	if err == nil {
		a.redisClient.Set(ctx, l2CacheKey, jsonData, a.config.KeyCacheTTL)
	}

	return publicKey, nil
}

func (a *VaultAdapter) getCachedPrivateKey(cacheKey string) (*rsa.PrivateKey, string, bool) {
	if item, found := a.l1Cache.Get(cacheKey); found {
		if entry, ok := item.(privateKeyCacheEntry); ok {
			return entry.key, entry.kid, true
		}
	}
	return nil, "", false
}

func (a *VaultAdapter) setCachedPrivateKey(cacheKey string, key *rsa.PrivateKey, kid string) {
	entry := privateKeyCacheEntry{key: key, kid: kid}
	a.l1Cache.Set(cacheKey, entry, 1*time.Minute) // Short TTL for private keys
}

type privateKeyCacheEntry struct {
	key *rsa.PrivateKey
	kid string
}

// EncryptSensitiveData is not implemented for the VaultAdapter.
func (a *VaultAdapter) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// DecryptSensitiveData is not implemented for the VaultAdapter.
func (a *VaultAdapter) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// GenerateJWT generates a new JWT for a tenant.
func (a *VaultAdapter) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (tokenString string, keyID string, err error) {
	privateKey, kid, err := a.GetPrivateKey(ctx, tenantID)
	if err != nil {
		return "", "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signedString, err := token.SignedString(privateKey)
	if err != nil {
		return "", "", err
	}

	return signedString, kid, nil
}

// VerifyJWT is not implemented for the VaultAdapter.
func (a *VaultAdapter) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	return nil, fmt.Errorf("not implemented")
}

// RotateKey is not implemented for the VaultAdapter.
func (a *VaultAdapter) RotateKey(ctx context.Context, tenantID string) (string, error) {
	return "", fmt.Errorf("not implemented")
}
