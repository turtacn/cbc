package cryptoadapter

import (
	"context"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v5"
	domain "github.com/turtacn/cbc/internal/domain/service"
	infra "github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/pkg/logger"
)

// ServiceAdapter adapts the infrastructure-level KeyManager to the domain's CryptoService interface.
type ServiceAdapter struct {
	KM  *infra.KeyManager
	Log logger.Logger
}

// NewServiceAdapter creates a new crypto service adapter.
func NewServiceAdapter(km *infra.KeyManager, log logger.Logger) domain.CryptoService {
	return &ServiceAdapter{KM: km, Log: log}
}

var _ domain.CryptoService = (*ServiceAdapter)(nil)

// GenerateJWT generates a new JWT by calling the underlying KeyManager.
func (s *ServiceAdapter) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
	return s.KM.GenerateJWT(ctx, tenantID, claims)
}

// VerifyJWT verifies a JWT by calling the underlying KeyManager.
func (s *ServiceAdapter) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	return s.KM.VerifyJWT(ctx, tokenString, tenantID)
}

// GetPublicKey retrieves a public key by calling the underlying KeyManager.
func (s *ServiceAdapter) GetPublicKey(ctx context.Context, tenantID string, keyID string) (*rsa.PublicKey, error) {
	return s.KM.GetPublicKey(ctx, tenantID, keyID)
}

// GetPrivateKey retrieves a private key by calling the underlying KeyManager.
func (s *ServiceAdapter) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	return s.KM.GetPrivateKey(ctx, tenantID)
}

// RotateKey rotates a key by calling the underlying KeyManager.
func (s *ServiceAdapter) RotateKey(ctx context.Context, tenantID string) (string, error) {
	return s.KM.RotateKey(ctx, tenantID)
}

// EncryptSensitiveData encrypts data by calling the underlying KeyManager.
func (s *ServiceAdapter) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return s.KM.EncryptSensitiveData(ctx, data)
}

// DecryptSensitiveData decrypts data by calling the underlying KeyManager.
func (s *ServiceAdapter) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return s.KM.DecryptSensitiveData(ctx, data)
}

// --- Placeholder Implementations for unused methods ---

func (s *ServiceAdapter) ParseJWT(tokenString string) (*jwt.Token, error) {
	return nil, errors.New("not implemented")
}

func (s *ServiceAdapter) GetPublicKeyJWKS(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	return nil, errors.New("not implemented")
}

func (s *ServiceAdapter) RevokeKey(ctx context.Context, tenantID string, keyID string, reason string) error {
	return errors.New("not implemented")
}

func (s *ServiceAdapter) ValidateJWTHeader(header map[string]interface{}) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *ServiceAdapter) ValidateStandardClaims(claims jwt.MapClaims, clockSkew int64) (bool, error) {
	return false, errors.New("not implemented")
}

func (s *ServiceAdapter) ExtractKeyID(tokenString string) (string, error) {
	return "", errors.New("not implemented")
}
