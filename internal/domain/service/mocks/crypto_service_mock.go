package mocks

import (
	"context"
	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
)

// MockCryptoService is a mock implementation of CryptoService
type MockCryptoService struct {
	mock.Mock
}

func (m *MockCryptoService) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	args := m.Called(ctx, data)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoService) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	args := m.Called(ctx, data)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoService) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
	args := m.Called(ctx, tenantID, claims)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockCryptoService) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	args := m.Called(ctx, tokenString, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(jwt.MapClaims), args.Error(1)
}

func (m *MockCryptoService) GetPublicKey(ctx context.Context, tenantID string, keyID string) (*rsa.PublicKey, error) {
	args := m.Called(ctx, tenantID, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

func (m *MockCryptoService) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).(*rsa.PrivateKey), args.String(1), args.Error(2)
}

func (m *MockCryptoService) RotateKey(ctx context.Context, tenantID string) (string, error) {
	args := m.Called(ctx, tenantID)
	return args.String(0), args.Error(1)
}
