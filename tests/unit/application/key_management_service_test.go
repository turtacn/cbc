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
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/domain/service/mocks"
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

type MockTenantRepository struct {
	mock.Mock
}

func (m *MockTenantRepository) FindByID(ctx context.Context, tenantID string) (*models.Tenant, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepository) Save(ctx context.Context, tenant *models.Tenant) error {
	return nil
}
func (m *MockTenantRepository) Update(ctx context.Context, tenant *models.Tenant) error {
	return nil
}
func (m *MockTenantRepository) FindByName(ctx context.Context, name string) (*models.Tenant, error) {
	return nil, nil
}
func (m *MockTenantRepository) FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	return nil, 0, nil
}
func (m *MockTenantRepository) FindActiveAll(ctx context.Context) ([]*models.Tenant, error) {
	return nil, nil
}
func (m *MockTenantRepository) Exists(ctx context.Context, tenantID string) (bool, error) {
	return false, nil
}
func (m *MockTenantRepository) UpdateStatus(ctx context.Context, tenantID string, status string) error {
	return nil
}
func (m *MockTenantRepository) UpdateRateLimitConfig(ctx context.Context, tenantID string, config *models.RateLimitConfig) error {
	return nil
}
func (m *MockTenantRepository) UpdateTokenTTLConfig(ctx context.Context, tenantID string, config *models.TokenTTLConfig) error {
	return nil
}
func (m *MockTenantRepository) UpdateKeyRotationPolicy(ctx context.Context, tenantID string, policy *models.KeyRotationPolicy) error {
	return nil
}
func (m *MockTenantRepository) Delete(ctx context.Context, tenantID string) error {
	return nil
}
func (m *MockTenantRepository) GetTenantMetrics(ctx context.Context, tenantID string) (*repository.TenantMetrics, error) {
	return nil, nil
}
func (m *MockTenantRepository) GetAllMetrics(ctx context.Context) (*repository.SystemMetrics, error) {
	return nil, nil
}
func (m *MockTenantRepository) IncrementRequestCount(ctx context.Context, tenantID string, count int64) error {
	return nil
}
func (m *MockTenantRepository) UpdateLastActivityAt(ctx context.Context, tenantID string, lastActivityAt time.Time) error {
	return nil
}

func TestKeyManagementService_CompromiseKey_CallsKLR(t *testing.T) {
	mockKeyRepo := new(MockKeyRepository)
	mockCDNManager := new(MockCDNCacheManager)
	mockKLR := new(mocks.KeyLifecycleRegistry)
	log := logger.NewNoopLogger()

	kms, err := application.NewKeyManagementService(
		nil,
		mockKeyRepo,
		nil, // tenantRepo not needed for this test
		nil, // policyEngine not needed for this test
		mockKLR,
		log,
	)
	assert.NoError(t, err)

	ctx := context.Background()
	tenantID := "test-tenant"
	kid := "test-kid"
	reason := "test-reason"

	// Set up mock expectations
	mockKeyRepo.On("UpdateKeyStatus", ctx, tenantID, kid, "compromised").Return(nil)
	mockKLR.On("LogEvent", ctx, mock.AnythingOfType("models.KLREvent")).Return(nil)
	mockCDNManager.On("PurgeTenantJWKS", ctx, tenantID).Return(nil)

	// Call the method
	err = kms.CompromiseKey(ctx, tenantID, kid, reason, mockCDNManager)

	// Assert the results
	assert.NoError(t, err)
	mockKeyRepo.AssertExpectations(t)
	mockKLR.AssertExpectations(t)
	mockCDNManager.AssertExpectations(t)
}

func TestKeyManagementService_RotateTenantKey_ChecksPolicy(t *testing.T) {
	mockKeyRepo := new(MockKeyRepository)
	mockCDNManager := new(MockCDNCacheManager)
	mockKeyProvider := new(MockKeyProvider)
	mockPolicyEngine := new(mocks.PolicyEngine)
	mockKLR := new(mocks.KeyLifecycleRegistry)
	mockTenantRepo := new(MockTenantRepository)
	log := logger.NewNoopLogger()

	keyProviders := map[string]service.KeyProvider{
		"vault": mockKeyProvider,
	}

	kms, err := application.NewKeyManagementService(
		keyProviders,
		mockKeyRepo,
		mockTenantRepo,
		mockPolicyEngine,
		mockKLR,
		log,
	)
	assert.NoError(t, err)

	ctx := context.Background()
	tenantID := "test-tenant"

	// Set up mock expectations
	mockTenantRepo.On("FindByID", ctx, tenantID).Return(&models.Tenant{TenantID: tenantID, ComplianceClass: "L1"}, nil)
	mockPolicyEngine.On("CheckKeyGeneration", ctx, mock.AnythingOfType("models.PolicyRequest")).Return(nil)
	mockKeyRepo.On("CreateKey", ctx, mock.AnythingOfType("*models.Key")).Return(nil)
	mockKLR.On("LogEvent", ctx, mock.AnythingOfType("models.KLREvent")).Return(nil)
	mockKeyRepo.On("GetActiveKeys", ctx, tenantID).Return([]*models.Key{}, nil)
	mockKeyRepo.On("GetDeprecatedKeys", ctx, tenantID).Return([]*models.Key{}, nil)
	mockCDNManager.On("PurgeTenantJWKS", ctx, tenantID).Return(nil)

	// Call the method
	_, err = kms.RotateTenantKey(ctx, tenantID, mockCDNManager)

	// Assert the results
	assert.NoError(t, err)
	mockTenantRepo.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
	mockKeyRepo.AssertExpectations(t)
	mockKLR.AssertExpectations(t)
	mockCDNManager.AssertExpectations(t)
}

func TestKeyManagementService_RotateTenantKey_PolicyFails(t *testing.T) {
	mockKeyRepo := new(MockKeyRepository)
	mockCDNManager := new(MockCDNCacheManager)
	mockKeyProvider := new(MockKeyProvider)
	mockPolicyEngine := new(mocks.PolicyEngine)
	mockKLR := new(mocks.KeyLifecycleRegistry)
	mockTenantRepo := new(MockTenantRepository)
	log := logger.NewNoopLogger()

	keyProviders := map[string]service.KeyProvider{
		"vault": mockKeyProvider,
	}

	kms, err := application.NewKeyManagementService(
		keyProviders,
		mockKeyRepo,
		mockTenantRepo,
		mockPolicyEngine,
		mockKLR,
		log,
	)
	assert.NoError(t, err)

	ctx := context.Background()
	tenantID := "test-tenant"

	// Set up mock expectations
	mockTenantRepo.On("FindByID", ctx, tenantID).Return(&models.Tenant{TenantID: tenantID, ComplianceClass: "L1"}, nil)
	mockPolicyEngine.On("CheckKeyGeneration", ctx, mock.AnythingOfType("models.PolicyRequest")).Return(errors.New("policy violation"))

	// Call the method
	_, err = kms.RotateTenantKey(ctx, tenantID, mockCDNManager)

	// Assert the results
	assert.Error(t, err)
	mockTenantRepo.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
	mockKeyRepo.AssertNotCalled(t, "CreateKey")
	mockKLR.AssertNotCalled(t, "LogEvent")
	mockCDNManager.AssertNotCalled(t, "PurgeTenantJWKS")
}
