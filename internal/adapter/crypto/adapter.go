package cryptoadapter

import (
	"context"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	domain "github.com/turtacn/cbc/internal/domain/service"
	infra "github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/pkg/logger"
)

type ServiceAdapter struct {
	KM  *infra.KeyManager
	Log logger.Logger
}

var _ domain.CryptoService = (*ServiceAdapter)(nil)

func (s *ServiceAdapter) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
	panic("implement me")
}

func (s *ServiceAdapter) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	panic("implement me")
}

func (s *ServiceAdapter) ParseJWT(tokenString string) (*jwt.Token, error) {
	panic("implement me")
}

func (s *ServiceAdapter) GetPublicKey(ctx context.Context, tenantID string, keyID string) (*rsa.PublicKey, error) {
	panic("implement me")
}

func (s *ServiceAdapter) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	panic("implement me")
}

func (s *ServiceAdapter) GetPublicKeyJWKS(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	panic("implement me")
}

func (s *ServiceAdapter) RotateKey(ctx context.Context, tenantID string) (string, error) {
	panic("implement me")
}

func (s *ServiceAdapter) RevokeKey(ctx context.Context, tenantID string, keyID string, reason string) error {
	panic("implement me")
}

func (s *ServiceAdapter) ValidateJWTHeader(header map[string]interface{}) (bool, error) {
	panic("implement me")
}

func (s *ServiceAdapter) ValidateStandardClaims(claims jwt.MapClaims, clockSkew int64) (bool, error) {
	panic("implement me")
}

func (s *ServiceAdapter) ExtractKeyID(tokenString string) (string, error) {
	panic("implement me")
}

func (s *ServiceAdapter) EncryptSensitiveData(plaintext string, tenantID string) (string, error) {
	panic("implement me")
}

func (s *ServiceAdapter) DecryptSensitiveData(ciphertext string, tenantID string) (string, error) {
	return ciphertext, nil
}
