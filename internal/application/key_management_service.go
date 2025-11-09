// Package application provides the application layer services.
package application

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// KeyManagementService is the application service for key management.
type KeyManagementService struct {
	keyProviders map[string]service.KeyProvider
	keyRepo      repository.KeyRepository
	logger       logger.Logger
}

// NewKeyManagementService creates a new KeyManagementService.
func NewKeyManagementService(keyProviders map[string]service.KeyProvider, keyRepo repository.KeyRepository, logger logger.Logger) (service.KeyManagementService, error) {
	return &KeyManagementService{
		keyProviders: keyProviders,
		keyRepo:      keyRepo,
		logger:       logger.WithComponent("KeyManagementService"),
	}, nil
}

// RotateTenantKey rotates the key for a tenant.
func (s *KeyManagementService) RotateTenantKey(ctx context.Context, tenantID string, cdnManager service.CDNCacheManager) (string, error) {
	provider, ok := s.keyProviders["vault"] // Assuming vault for now
	if !ok {
		return "", fmt.Errorf("no vault key provider configured")
	}

	kid, providerRef, publicKey, err := provider.GenerateKey(ctx, models.KeySpec{Algorithm: "RSA", Bits: 2048})
	if err != nil {
		return "", fmt.Errorf("failed to generate new key: %w", err)
	}

	publicKeyPEM, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	newKey := &models.Key{
		ID:           kid,
		TenantID:     tenantID,
		ProviderType: "vault",
		ProviderRef:  providerRef,
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyPEM})),
		Status:       "active",
	}

	if err := s.keyRepo.CreateKey(ctx, newKey); err != nil {
		return "", fmt.Errorf("failed to save new key: %w", err)
	}

	deprecatedKeys, err := s.keyRepo.GetActiveKeys(ctx, tenantID)
	if err != nil {
		s.logger.Error(ctx, "failed to get active keys for deprecation", err)
		// Continue anyway, the new key is already active
	}

	for _, key := range deprecatedKeys {
		if key.ID != kid {
			if err := s.keyRepo.UpdateKeyStatus(ctx, tenantID, key.ID, "deprecated"); err != nil {
				s.logger.Error(ctx, "failed to deprecate key", err, logger.String("kid", key.ID))
			}
		}
	}

	revokedKeys, err := s.keyRepo.GetDeprecatedKeys(ctx, tenantID)
	if err != nil {
		s.logger.Error(ctx, "failed to get deprecated keys for revocation", err)
		// Continue
	}

	for _, key := range revokedKeys {
		if err := s.keyRepo.UpdateKeyStatus(ctx, tenantID, key.ID, "revoked"); err != nil {
			s.logger.Error(ctx, "failed to revoke key", err, logger.String("kid", key.ID))
		}
	}

	if err := cdnManager.PurgeTenantJWKS(ctx, tenantID); err != nil {
		s.logger.Error(ctx, "failed to purge cdn cache for tenant", err, logger.String("tenantID", tenantID))
		// Do not return error, as the key rotation is already complete
	}

	return kid, nil
}

// GetTenantPublicKeys retrieves the public keys for a tenant.
func (s *KeyManagementService) GetTenantPublicKeys(ctx context.Context, tenantID string) (map[string]*rsa.PublicKey, error) {
	keys, err := s.keyRepo.GetActiveKeys(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active keys: %w", err)
	}

	deprecatedKeys, err := s.keyRepo.GetDeprecatedKeys(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get deprecated keys: %w", err)
	}

	keys = append(keys, deprecatedKeys...)

	publicKeys := make(map[string]*rsa.PublicKey, len(keys))
	for _, key := range keys {
		block, _ := pem.Decode([]byte(key.PublicKeyPEM))
		if block == nil {
			s.logger.Error(ctx, "failed to decode PEM block for key", nil, logger.String("kid", key.ID))
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			s.logger.Error(ctx, "failed to parse public key", err, logger.String("kid", key.ID))
			continue
		}
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			publicKeys[key.ID] = rsaPub
		}
	}

	return publicKeys, nil
}

// CompromiseKey marks a key as compromised.
func (s *KeyManagementService) CompromiseKey(ctx context.Context, tenantID, kid, reason string, cdnManager service.CDNCacheManager) error {
	if err := s.keyRepo.UpdateKeyStatus(ctx, tenantID, kid, "compromised"); err != nil {
		return err
	}

	if err := cdnManager.PurgeTenantJWKS(ctx, tenantID); err != nil {
		s.logger.Error(ctx, "failed to purge cdn cache for tenant", err, logger.String("tenantID", tenantID))
		// Do not return error, as the key is already compromised in the database
	}

	return nil
}

// GenerateJWT generates a JWT for a tenant.
func (s *KeyManagementService) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
	activeKeys, err := s.keyRepo.GetActiveKeys(ctx, tenantID)
	if err != nil || len(activeKeys) == 0 {
		return "", "", fmt.Errorf("no active key found for tenant %s", tenantID)
	}
	activeKey := activeKeys[0]

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = activeKey.ID

	signedString, err := token.SignedString(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedString, activeKey.ID, nil
}

// VerifyJWT verifies a JWT for a tenant.
func (s *KeyManagementService) VerifyJWT(ctx context.Context, tokenString, tenantID string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		key, err := s.keyRepo.GetKeyByKID(ctx, tenantID, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get key by kid: %w", err)
		}
		if key.Status == "compromised" || key.Status == "revoked" {
			return nil, fmt.Errorf("key is not valid")
		}

		block, _ := pem.Decode([]byte(key.PublicKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return pub, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
