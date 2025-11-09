// Package application_test provides tests for the application package.
package application_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

type MockKeyProvider struct {
	mock.Mock
}

func (m *MockKeyProvider) GenerateKey(ctx context.Context, keySpec models.KeySpec) (string, string, *rsa.PublicKey, error) {
	args := m.Called(ctx, keySpec)
	return args.String(0), args.String(1), args.Get(2).(*rsa.PublicKey), args.Error(3)
}

func (m *MockKeyProvider) Sign(ctx context.Context, providerRef string, digest []byte) ([]byte, error) {
	args := m.Called(ctx, providerRef, digest)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockKeyProvider) GetPublicKey(ctx context.Context, providerRef string) (*rsa.PublicKey, error) {
	args := m.Called(ctx, providerRef)
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

func (m *MockKeyProvider) Backup(ctx context.Context, providerRef string) ([]byte, error) {
	args := m.Called(ctx, providerRef)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockKeyProvider) Restore(ctx context.Context, encryptedBlob []byte) (string, error) {
	args := m.Called(ctx, encryptedBlob)
	return args.String(0), args.Error(1)
}

type MockKeyRepository struct {
	mock.Mock
}

func (m *MockKeyRepository) CreateKey(ctx context.Context, key *models.Key) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockKeyRepository) GetKeyByKID(ctx context.Context, tenantID, kid string) (*models.Key, error) {
	args := m.Called(ctx, tenantID, kid)
	return args.Get(0).(*models.Key), args.Error(1)
}

func (m *MockKeyRepository) GetActiveKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).([]*models.Key), args.Error(1)
}

func (m *MockKeyRepository) GetDeprecatedKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).([]*models.Key), args.Error(1)
}

func (m *MockKeyRepository) UpdateKeyStatus(ctx context.Context, tenantID, kid, status string) error {
	args := m.Called(ctx, tenantID, kid, status)
	return args.Error(0)
}

func TestKeyManagementService_RotateTenantKey(t *testing.T) {
	mockKeyProvider := new(MockKeyProvider)
	mockKeyRepo := new(MockKeyRepository)
	logger := logger.NewNoopLogger()

	keyProviders := map[string]service.KeyProvider{
		"vault": mockKeyProvider,
	}

	kms, err := application.NewKeyManagementService(keyProviders, mockKeyRepo, logger)
	assert.NoError(t, err)

	ctx := context.Background()
	tenantID := "test-tenant"

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	publicKey := &privateKey.PublicKey

	mockKeyProvider.On("GenerateKey", ctx, mock.Anything).Return("new-kid", "new-ref", publicKey, nil)
	mockKeyRepo.On("CreateKey", ctx, mock.Anything).Return(nil)
	mockKeyRepo.On("GetActiveKeys", ctx, tenantID).Return([]*models.Key{{ID: "old-kid"}}, nil)
	mockKeyRepo.On("UpdateKeyStatus", ctx, tenantID, "old-kid", "deprecated").Return(nil)
	mockKeyRepo.On("GetDeprecatedKeys", ctx, tenantID).Return([]*models.Key{}, nil)

	kid, err := kms.RotateTenantKey(ctx, tenantID)
	assert.NoError(t, err)
	assert.Equal(t, "new-kid", kid)

	mockKeyProvider.AssertExpectations(t)
	mockKeyRepo.AssertExpectations(t)
}
