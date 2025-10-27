// internal/infrastructure/crypto/jwt_manager_test.go
package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// MockKeyManagementService is a mock implementation of the KeyManagementService interface.
type MockKeyManagementService struct {
	mock.Mock
}

func (m *MockKeyManagementService) GetActiveKeyForTenant(ctx context.Context, tenantID string) (*KeyPair, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*KeyPair), args.Error(1)
}

func (m *MockKeyManagementService) GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error) {
	args := m.Called(ctx, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*KeyPair), args.Error(1)
}

func (m *MockKeyManagementService) ListTenantKeys(ctx context.Context, tenantID string) ([]*KeyMetadata, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*KeyMetadata), args.Error(1)
}

// generateTestKeyPair creates a real RSA key pair and returns it in the KeyPair struct format with PEM strings.
func generateTestKeyPair(t *testing.T, tenantID string) *KeyPair {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return &KeyPair{
		ID:         "test-key-" + uuid.New().String(),
		PrivateKey: string(privPEM),
		PublicKey:  string(pubPEM),
		Algorithm:  RSA2048,
		TenantID:   tenantID,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
		Status:     KeyStatusActive,
	}
}

func TestJWTManager_GenerateJWT(t *testing.T) {
	log := logger.NewDefaultLogger()
	config := &JWTConfig{
		Issuer:     "cbc-auth-service",
		Algorithm:  "RS256",
		DefaultTTL: 15 * time.Minute,
		Audience:   []string{"cbc-api"},
	}

	mockKeyManager := new(MockKeyManagementService)

	manager, err := NewJWTManager(mockKeyManager, config, log)
	require.NoError(t, err)

	ctx := context.Background()
	tenantID := uuid.New().String()
	keyPair := generateTestKeyPair(t, tenantID)

	tokenModel := &models.Token{
		JTI:       uuid.New().String(),
		TenantID:  tenantID,
		DeviceID:  uuid.New().String(),
		TokenType: constants.TokenTypeAccess,
		Scope:     "agent:read",
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	t.Run("Successfully generate token", func(t *testing.T) {
		mockKeyManager.On("GetActiveKeyForTenant", ctx, tenantID).Return(keyPair, nil).Once()

		tokenString, err := manager.GenerateJWT(ctx, tokenModel)

		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify the token can be parsed with the public key
		parsedKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(keyPair.PublicKey))
		require.NoError(t, err)
		parsedToken, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
			return parsedKey, nil
		})
		require.NoError(t, err)
		claims, ok := parsedToken.Claims.(*CustomClaims)
		require.True(t, ok)

		assert.Equal(t, tokenModel.JTI, claims.ID)
		assert.Equal(t, tokenModel.TenantID, claims.TenantID)
		assert.Contains(t, claims.Audience, "cbc-api")

		mockKeyManager.AssertExpectations(t)
	})

	t.Run("KeyManager returns an error", func(t *testing.T) {
		expectedErr := errors.New(errors.CodeInternal, "failed to get signing key")
		mockKeyManager.On("GetActiveKeyForTenant", ctx, tenantID).Return(nil, expectedErr).Once()

		tokenString, err := manager.GenerateJWT(ctx, tokenModel)

		assert.Error(t, err)
		assert.Empty(t, tokenString)
		assert.Contains(t, err.Error(), expectedErr.Error())

		mockKeyManager.AssertExpectations(t)
	})
}

func TestJWTManager_VerifyJWT(t *testing.T) {
	log := logger.NewDefaultLogger()
	config := &JWTConfig{
		Issuer:     "cbc-auth-service",
		Algorithm:  "RS256",
		DefaultTTL: 15 * time.Minute,
		Audience:   []string{"cbc-api"},
	}
	mockKeyManager := new(MockKeyManagementService)
	manager, err := NewJWTManager(mockKeyManager, config, log)
	require.NoError(t, err)

	ctx := context.Background()
	tenantID := uuid.New().String()

	// Create a valid token for testing
	validKeyPair := generateTestKeyPair(t, tenantID)
	validTokenModel := &models.Token{
		JTI:       uuid.New().String(),
		TenantID:  tenantID,
		DeviceID:  uuid.New().String(),
		TokenType: constants.TokenTypeAccess,
		IssuedAt:  time.Now(),
	}

	// We need a temporary manager with a real key to sign the token
	tempMock := new(MockKeyManagementService)
	tempManager, _ := NewJWTManager(tempMock, config, log)
	tempMock.On("GetActiveKeyForTenant", ctx, tenantID).Return(validKeyPair, nil)
	validTokenString, err := tempManager.GenerateJWT(ctx, validTokenModel)
	require.NoError(t, err)

	// Create an expired token for testing
	expiredConfig := &JWTConfig{
		Issuer:     "cbc-auth-service",
		Algorithm:  "RS256",
		DefaultTTL: -1 * time.Minute,
		Audience:   []string{"cbc-api"},
	}
	expiredTempManager, _ := NewJWTManager(tempMock, expiredConfig, log)
	expiredTokenModel := &models.Token{
		JTI:       uuid.New().String(),
		TenantID:  tenantID,
		DeviceID:  uuid.New().String(),
		TokenType: constants.TokenTypeAccess,
		IssuedAt:  time.Now().Add(-2 * time.Minute),
	}
	expiredTokenString, err := expiredTempManager.GenerateJWT(ctx, expiredTokenModel)
	require.NoError(t, err)

	t.Run("Successfully verify a valid token", func(t *testing.T) {
		mockKeyManager.On("GetKeyPair", ctx, validKeyPair.ID).Return(validKeyPair, nil).Once()

		claims, err := manager.VerifyJWT(ctx, validTokenString)
		assert.NoError(t, err)
		require.NotNil(t, claims)
		assert.Equal(t, validTokenModel.JTI, claims.ID)
		assert.Equal(t, validTokenModel.TenantID, claims.TenantID)

		mockKeyManager.AssertExpectations(t)
	})

	t.Run("Fail verification on expired token", func(t *testing.T) {
		mockKeyManager.On("GetKeyPair", ctx, validKeyPair.ID).Return(validKeyPair, nil).Once()

		claims, err := manager.VerifyJWT(ctx, expiredTokenString)
		assert.Error(t, err)
		assert.Nil(t, claims)

		cbcErr, ok := errors.AsCBCError(err)
		require.True(t, ok)
		assert.Equal(t, constants.ErrorCode(errors.CodeUnauthenticated), cbcErr.Code())
	})
}
