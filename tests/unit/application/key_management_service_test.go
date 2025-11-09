//go:build unit

package application_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// MockKeyProvider is a mock implementation of the KeyProvider interface.
type MockKeyProvider struct {
	mock.Mock
}

func (m *MockKeyProvider) GenerateKey(ctx context.Context, keySpec models.KeySpec) (string, string, *rsa.PublicKey, error) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "mock-kid"
	return kid, "mock-ref", &privateKey.PublicKey, nil
}

func (m *MockKeyProvider) Sign(ctx context.Context, providerRef string, digest []byte) ([]byte, error) {
	return nil, nil
}

func (m *MockKeyProvider) GetPublicKey(ctx context.Context, providerRef string) (*rsa.PublicKey, error) {
	return nil, nil
}

func (m *MockKeyProvider) Backup(ctx context.Context, providerRef string) ([]byte, error) {
	return nil, nil
}

func (m *MockKeyProvider) Restore(ctx context.Context, encryptedBlob []byte) (string, error) {
	return "", nil
}

// MockKeyRepository is a mock implementation of the KeyRepository interface.
type MockKeyRepository struct {
	mock.Mock
}

func (m *MockKeyRepository) CreateKey(ctx context.Context, key *models.Key) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockKeyRepository) GetActiveKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Key), args.Error(1)
}

func (m *MockKeyRepository) GetDeprecatedKeys(ctx context.Context, tenantID string) ([]*models.Key, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Key), args.Error(1)
}

func (m *MockKeyRepository) GetKeyByKID(ctx context.Context, tenantID, kid string) (*models.Key, error) {
	args := m.Called(ctx, tenantID, kid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Key), args.Error(1)
}

func (m *MockKeyRepository) UpdateKeyStatus(ctx context.Context, tenantID, kid, status string) error {
	args := m.Called(ctx, tenantID, kid, status)
	return args.Error(0)
}

// MockCDNCacheManager is a mock implementation of the CDNCacheManager interface.
type MockCDNCacheManager struct {
	mock.Mock
}

func (m *MockCDNCacheManager) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *MockCDNCacheManager) PurgePath(ctx context.Context, path string) error {
	args := m.Called(ctx, path)
	return args.Error(0)
}

func TestKeyManagementService_CompromiseKey_PurgesCache(t *testing.T) {
	mockKeyRepo := new(MockKeyRepository)
	mockCDNManager := new(MockCDNCacheManager)
	log := logger.NewNoopLogger()

	kms, err := application.NewKeyManagementService(nil, mockKeyRepo, mockCDNManager, log)
	assert.NoError(t, err)

	ctx := context.Background()
	tenantID := "test-tenant"
	kid := "test-kid"
	reason := "test-reason"

	// Set up mock expectations
	mockKeyRepo.On("UpdateKeyStatus", ctx, tenantID, kid, "compromised").Return(nil)
	mockCDNManager.On("PurgeTenantJWKS", ctx, tenantID).Return(nil)

	// Call the method
	err = kms.CompromiseKey(ctx, tenantID, kid, reason)

	// Assert the results
	assert.NoError(t, err)
	mockKeyRepo.AssertExpectations(t)
	mockCDNManager.AssertExpectations(t)
}

func TestKeyManagementService_RotateTenantKey_PurgesCache(t *testing.T) {
	mockKeyRepo := new(MockKeyRepository)
	mockCDNManager := new(MockCDNCacheManager)
	mockKeyProvider := new(MockKeyProvider)
	log := logger.NewNoopLogger()

	keyProviders := map[string]service.KeyProvider{
		"vault": mockKeyProvider,
	}

	kms, err := application.NewKeyManagementService(keyProviders, mockKeyRepo, mockCDNManager, log)
	assert.NoError(t, err)

	ctx := context.Background()
	tenantID := "test-tenant"

	// Set up mock expectations
	mockKeyRepo.On("CreateKey", ctx, mock.AnythingOfType("*models.Key")).Return(nil)
	mockKeyRepo.On("GetActiveKeys", ctx, tenantID).Return([]*models.Key{}, nil)
	mockKeyRepo.On("GetDeprecatedKeys", ctx, tenantID).Return([]*models.Key{}, nil)
	mockCDNManager.On("PurgeTenantJWKS", ctx, tenantID).Return(nil)

	// Call the method
	_, err = kms.RotateTenantKey(ctx, tenantID)

	// Assert the results
	assert.NoError(t, err)
	mockKeyRepo.AssertExpectations(t)
	mockCDNManager.AssertExpectations(t)
}

func TestKeyManagementService_CompromiseKey_PurgeFails(t *testing.T) {
	mockKeyRepo := new(MockKeyRepository)
	mockCDNManager := new(MockCDNCacheManager)
	log := logger.NewNoopLogger()

	kms, err := application.NewKeyManagementService(nil, mockKeyRepo, mockCDNManager, log)
	assert.NoError(t, err)

	ctx := context.Background()
	tenantID := "test-tenant"
	kid := "test-kid"
	reason := "test-reason"

	// Set up mock expectations
	mockKeyRepo.On("UpdateKeyStatus", ctx, tenantID, kid, "compromised").Return(nil)
	mockCDNManager.On("PurgeTenantJWKS", ctx, tenantID).Return(errors.New("purge failed"))

	// Call the method
	err = kms.CompromiseKey(ctx, tenantID, kid, reason)

	// Assert the results
	assert.NoError(t, err)
	mockKeyRepo.AssertExpectations(t)
	mockCDNManager.AssertExpectations(t)
}
