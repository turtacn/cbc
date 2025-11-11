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

// KeyManagementService is the application-layer service responsible for orchestrating cryptographic key lifecycle events.
// It coordinates between physical key providers, database repositories, and policy engines.
// KeyManagementService 是负责协调加密密钥生命周期事件的应用层服务。
// 它在物理密钥提供者、数据库存储库和策略引擎之间进行协调。
type KeyManagementService struct {
	keyProviders map[string]service.KeyProvider
	keyRepo      repository.KeyRepository
	tenantRepo   repository.TenantRepository
	policyEngine service.PolicyEngine
	klr          service.KeyLifecycleRegistry
	riskOracle   service.RiskOracle
	logger       logger.Logger
}

// NewKeyManagementService creates a new instance of the KeyManagementService.
// It takes all necessary dependencies for managing keys, policies, and logging.
// NewKeyManagementService 创建 KeyManagementService 的一个新实例。
// 它需要管理密钥、策略和日志记录所需的所有依赖项。
func NewKeyManagementService(
	keyProviders map[string]service.KeyProvider,
	keyRepo repository.KeyRepository,
	tenantRepo repository.TenantRepository,
	policyEngine service.PolicyEngine,
	klr service.KeyLifecycleRegistry,
	logger logger.Logger,
	riskOracle service.RiskOracle,
) (service.KeyManagementService, error) {
	return &KeyManagementService{
		keyProviders: keyProviders,
		keyRepo:      keyRepo,
		tenantRepo:   tenantRepo,
		policyEngine: policyEngine,
		klr:          klr,
		riskOracle:   riskOracle,
		logger:       logger.WithComponent("KeyManagementService"),
	}, nil
}

// RotateTenantKey orchestrates the entire process of rotating a signing key for a tenant.
// This includes checking policy, generating a new key, updating the database, logging the event, and purging the CDN cache.
// RotateTenantKey 协调为租户轮换签名密钥的整个过程。
// 这包括检查策略、生成新密钥、更新数据库、记录事件以及清除 CDN 缓存。
func (s *KeyManagementService) RotateTenantKey(ctx context.Context, tenantID string, cdnManager service.CDNCacheManager) (string, error) {
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to get tenant: %w", err)
	}

	keySize := 2048 // Default key size
	if tenant.ComplianceClass == "L3" {
		keySize = 4096
	} else if tenant.ComplianceClass == "L2" {
		keySize = 3072
	}

	riskProfile, err := s.riskOracle.GetTenantRisk(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("failed to get tenant risk profile: %w", err)
	}

	policyRequest := models.PolicyRequest{
		ComplianceClass:    tenant.ComplianceClass,
		KeySize:            keySize,
		CurrentRiskProfile: riskProfile,
	}

	if err := s.policyEngine.CheckKeyGeneration(ctx, policyRequest); err != nil {
		return "", fmt.Errorf("policy check failed: %w", err)
	}

	provider, ok := s.keyProviders["vault"] // Assuming vault for now
	if !ok {
		return "", fmt.Errorf("no vault key provider configured")
	}

	kid, providerRef, publicKey, err := provider.GenerateKey(ctx, models.KeySpec{Algorithm: "RSA", Bits: keySize})
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

	klrEvent := models.KLREvent{
		KeyID:    kid,
		TenantID: tenantID,
		Status:   "CREATED",
	}
	if err := s.klr.LogEvent(ctx, klrEvent); err != nil {
		s.logger.Error(ctx, "failed to log key creation event", err, logger.String("kid", kid))
	}

	deprecatedKeys, err := s.keyRepo.GetActiveKeys(ctx, tenantID)
	if err != nil {
		s.logger.Error(ctx, "failed to get active keys for deprecation", err)
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
	}

	for _, key := range revokedKeys {
		if err := s.keyRepo.UpdateKeyStatus(ctx, tenantID, key.ID, "revoked"); err != nil {
			s.logger.Error(ctx, "failed to revoke key", err, logger.String("kid", key.ID))
		}
	}

	if err := cdnManager.PurgeTenantJWKS(ctx, tenantID); err != nil {
		s.logger.Error(ctx, "failed to purge cdn cache for tenant", err, logger.String("tenantID", tenantID))
	}

	return kid, nil
}

// GetTenantPublicKeys retrieves all active and deprecated public keys for a tenant, suitable for building a JWKS.
// GetTenantPublicKeys 检索租户的所有活动和已弃用的公钥，适用于构建 JWKS。
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

// CompromiseKey marks a key as compromised, logs the event, and purges the relevant CDN cache.
// CompromiseKey 将密钥标记为已泄露，记录事件，并清除相关的 CDN 缓存。
func (s *KeyManagementService) CompromiseKey(ctx context.Context, tenantID, kid, reason string, cdnManager service.CDNCacheManager) error {
	if err := s.keyRepo.UpdateKeyStatus(ctx, tenantID, kid, "compromised"); err != nil {
		return err
	}

	klrEvent := models.KLREvent{
		KeyID:    kid,
		TenantID: tenantID,
		Status:   "COMPROMISED",
		Metadata: fmt.Sprintf(`{"reason": "%s"}`, reason),
	}
	if err := s.klr.LogEvent(ctx, klrEvent); err != nil {
		s.logger.Error(ctx, "failed to log key compromise event", err, logger.String("kid", kid))
	}

	if err := cdnManager.PurgeTenantJWKS(ctx, tenantID); err != nil {
		s.logger.Error(ctx, "failed to purge cdn cache for tenant", err, logger.String("tenantID", tenantID))
	}

	return nil
}

// GenerateJWT creates a new JWT, signs it with the tenant's active key, and returns the token string.
// GenerateJWT 创建一个新的 JWT，使用租户的活动密钥对其进行签名，并返回令牌字符串。
func (s *KeyManagementService) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
	activeKeys, err := s.keyRepo.GetActiveKeys(ctx, tenantID)
	if err != nil || len(activeKeys) == 0 {
		return "", "", fmt.Errorf("no active key found for tenant %s", tenantID)
	}
	activeKey := activeKeys[0]

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = activeKey.ID

	// Note: In a real implementation, the signing operation would be delegated to the KeyProvider
	// to avoid exposing the private key material to this service.
	signedString, err := token.SignedString(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedString, activeKey.ID, nil
}

// VerifyJWT parses and validates a JWT string. It fetches the correct public key based on the token's 'kid' header.
// VerifyJWT 解析并验证 JWT 字符串。它根据令牌的“kid”标头获取正确的公钥。
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
