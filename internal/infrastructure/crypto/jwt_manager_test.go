package crypto_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/crypto"
	"github.com/turtacn/cbc/pkg/errors"
)

// MockKeyManager is a mock of KeyManager
type MockKeyManager struct {
	mock.Mock
}

func (m *MockKeyManager) GetPrivateKey(ctx context.Context, tenantID uuid.UUID) (*rsa.PrivateKey, string, *errors.AppError) {
	args := m.Called(ctx, tenantID)
	if args.Get(2) == nil {
		return args.Get(0).(*rsa.PrivateKey), args.String(1), nil
	}
	return args.Get(0).(*rsa.PrivateKey), args.String(1), args.Get(2).(*errors.AppError)
}
func (m *MockKeyManager) GetPublicKey(ctx context.Context, tenantID uuid.UUID, keyID string) (*rsa.PublicKey, *errors.AppError) {
	args := m.Called(ctx, tenantID, keyID)
	if args.Get(1) == nil {
		return args.Get(0).(*rsa.PublicKey), nil
	}
	return args.Get(0).(*rsa.PublicKey), args.Get(1).(*errors.AppError)
}

func (m *MockKeyManager) RotateKey(ctx context.Context, tenantID uuid.UUID) (string, *errors.AppError) {
	args := m.Called(ctx, tenantID)
	if args.Get(1) == nil {
		return args.String(0), nil
	}
	return args.String(0), args.Get(1).(*errors.AppError)
}

func TestJWTManager_GenerateAndVerify(t *testing.T) {
	mockKeyManager := new(MockKeyManager)
	jwtManager := crypto.NewJWTManager(mockKeyManager, nil) // Real implementation needs logger

	// Generate a real RSA key pair for this test
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	publicKey := &privateKey.PublicKey

	token := models.NewToken(uuid.New(), uuid.New(), "access_token", time.Hour, "read", nil, "test")

	// Setup expectations
	mockKeyManager.On("GetPrivateKey", mock.Anything, token.TenantID).Return(privateKey, "test-key-id", nil)
	mockKeyManager.On("GetPublicKey", mock.Anything, token.TenantID, "test-key-id").Return(publicKey, nil)

	// Test GenerateJWT
	tokenString, appErr := jwtManager.GenerateJWT(context.Background(), token)
	assert.Nil(t, appErr)
	assert.NotEmpty(t, tokenString)

	// Test VerifyJWT
	claims, appErr := jwtManager.VerifyJWT(context.Background(), tokenString, token.TenantID)
	assert.Nil(t, appErr)
	assert.Equal(t, token.JTI, claims.ID)

	mockKeyManager.AssertExpectations(t)
}

//Personal.AI order the ending
