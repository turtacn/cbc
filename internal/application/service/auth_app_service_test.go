
// internal/application/service/auth_app_service_test.go
package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	domainservice "github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// Mock implementations for dependencies
type MockTenantRepo struct {
	mock.Mock
}

func (m *MockTenantRepo) FindByID(ctx context.Context, id string) (*models.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepo) Save(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockTenantRepo) Update(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockTenantRepo) FindByName(ctx context.Context, name string) (*models.Tenant, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepo) FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(1)
	}
	return args.Get(0).([]*models.Tenant), args.Get(1).(int64), args.Error(2)
}

func (m *MockTenantRepo) FindActiveAll(ctx context.Context) ([]*models.Tenant, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Tenant), args.Error(1)
}

func (m *MockTenantRepo) Exists(ctx context.Context, tenantID string) (bool, error) {
	args := m.Called(ctx, tenantID)
	return args.Bool(0), args.Error(1)
}

func (m *MockTenantRepo) UpdateStatus(ctx context.Context, tenantID string, status constants.TenantStatus) error {
	args := m.Called(ctx, tenantID, status)
	return args.Error(0)
}

func (m *MockTenantRepo) UpdateRateLimitConfig(ctx context.Context, tenantID string, config *models.RateLimitConfig) error {
	args := m.Called(ctx, tenantID, config)
	return args.Error(0)
}

func (m *MockTenantRepo) UpdateTokenTTLConfig(ctx context.Context, tenantID string, config *models.TokenTTLConfig) error {
	args := m.Called(ctx, tenantID, config)
	return args.Error(0)
}

func (m *MockTenantRepo) UpdateKeyRotationPolicy(ctx context.Context, tenantID string, policy *models.KeyRotationPolicy) error {
	args := m.Called(ctx, tenantID, policy)
	return args.Error(0)
}

func (m *MockTenantRepo) Delete(ctx context.Context, tenantID string) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *MockTenantRepo) GetTenantMetrics(ctx context.Context, tenantID string) (*repository.TenantMetrics, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.TenantMetrics), args.Error(1)
}

func (m *MockTenantRepo) GetAllMetrics(ctx context.Context) (*repository.SystemMetrics, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.SystemMetrics), args.Error(1)
}

func (m *MockTenantRepo) IncrementRequestCount(ctx context.Context, tenantID string, count int64) error {
	args := m.Called(ctx, tenantID, count)
	return args.Error(0)
}

func (m *MockTenantRepo) UpdateLastActivityAt(ctx context.Context, tenantID string, lastActivityAt time.Time) error {
	args := m.Called(ctx, tenantID, lastActivityAt)
	return args.Error(0)
}

type MockDeviceRepo struct {
	mock.Mock
}

func (m *MockDeviceRepo) FindByID(ctx context.Context, id string) (*models.Device, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

func (m *MockDeviceRepo) Save(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockDeviceRepo) Update(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockDeviceRepo) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockDeviceRepo) FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Device, int64, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(1)
	}
	return args.Get(0).([]*models.Device), args.Get(1).(int64), args.Error(2)
}
func (m *MockDeviceRepo) FindByFingerprint(ctx context.Context, tenantID, fingerprint string) (*models.Device, error) {
	args := m.Called(ctx, tenantID, fingerprint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

func (m *MockDeviceRepo) Exists(ctx context.Context, agentID string) (bool, error) {
	args := m.Called(ctx, agentID)
	return args.Bool(0), args.Error(1)
}

func (m *MockDeviceRepo) UpdateLastSeen(ctx context.Context, agentID string, lastSeenAt time.Time) error {
	args := m.Called(ctx, agentID, lastSeenAt)
	return args.Error(0)
}

func (m *MockDeviceRepo) UpdateTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error {
	args := m.Called(ctx, agentID, trustLevel)
	return args.Error(0)
}

func (m *MockDeviceRepo) UpdateStatus(ctx context.Context, agentID string, status constants.DeviceStatus) error {
	args := m.Called(ctx, agentID, status)
	return args.Error(0)
}

func (m *MockDeviceRepo) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockDeviceRepo) CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockDeviceRepo) FindInactiveDevices(ctx context.Context, inactiveSince time.Time, limit, offset int) ([]*models.Device, int64, error) {
	args := m.Called(ctx, inactiveSince, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(1)
	}
	return args.Get(0).([]*models.Device), args.Get(1).(int64), args.Error(2)
}

func (m *MockDeviceRepo) FindByTrustLevel(ctx context.Context, tenantID string, trustLevel constants.TrustLevel, limit, offset int) ([]*models.Device, int64, error) {
	args := m.Called(ctx, tenantID, trustLevel, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(1)
	}
	return args.Get(0).([]*models.Device), args.Get(1).(int64), args.Error(2)
}
func (m *MockDeviceRepo) BatchUpdateLastSeen(ctx context.Context, updates map[string]time.Time) error {
	args := m.Called(ctx, updates)
	return args.Error(0)
}

type MockTokenDomainService struct {
	mock.Mock
}

func (m *MockTokenDomainService) IssueToken(ctx context.Context, tenantID, subject string, scope []string) (*models.Token, error) {
	args := m.Called(ctx, tenantID, subject, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenDomainService) IssueTokenPair(ctx context.Context, tenantID, agentID, deviceFingerprint string, scope []string, metadata map[string]interface{}) (*models.Token, *models.Token, error) {
	args := m.Called(ctx, tenantID, agentID, deviceFingerprint, scope, metadata)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), args.Error(2)
}
func (m *MockTokenDomainService) VerifyToken(ctx context.Context, tokenString string, expectedType constants.TokenType, tenantID string) (*models.Token, error) {
	args := m.Called(ctx, tokenString, expectedType, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenDomainService) RevokeToken(ctx context.Context, jti, tenantID, reason string) error {
	args := m.Called(ctx, jti, tenantID, reason)
	return args.Error(0)
}

func (m *MockTokenDomainService) RefreshToken(ctx context.Context, refreshTokenString string, scopes []string) (*models.Token, *models.Token, error) {
	args := m.Called(ctx, refreshTokenString, scopes)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), args.Error(2)
}

func (m *MockTokenDomainService) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	args := m.Called(ctx, jti)
	return args.Bool(0), args.Error(1)
}
func (m *MockTokenDomainService) CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockTokenDomainService) GenerateAccessToken(ctx context.Context, refreshToken *models.Token, ttl *time.Duration, scope string, trustLevel string) (*models.Token, error) {
	args := m.Called(ctx, refreshToken, ttl, scope, trustLevel)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}
func (m *MockTokenDomainService) ValidateTokenClaims(ctx context.Context, token *models.Token, validationContext map[string]interface{}) (bool, error) {
	args := m.Called(ctx, token, validationContext)
	return args.Bool(0), args.Error(1)
}
func (m *MockTokenDomainService) IntrospectToken(ctx context.Context, tokenString string, tokenTypeHint string) (*models.TokenIntrospection, error) {
	args := m.Called(ctx, tokenString, tokenTypeHint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenIntrospection), args.Error(1)
}

type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) Allow(ctx context.Context, dimension domainservice.RateLimitDimension, identifier, action string) (bool, int, time.Time, error) {
	args := m.Called(ctx, dimension, identifier, action)
	return args.Bool(0), args.Int(1), args.Get(2).(time.Time), args.Error(3)
}
func (m *MockRateLimiter) AllowN(ctx context.Context, dimension domainservice.RateLimitDimension, identifier, action string, n int) (bool, int, time.Time, error) {
	args := m.Called(ctx, dimension, identifier, action, n)
	return args.Bool(0), args.Int(1), args.Get(2).(time.Time), args.Error(3)
}
func (m *MockRateLimiter) ResetLimit(ctx context.Context, dimension domainservice.RateLimitDimension, identifier, action string) error {
	args := m.Called(ctx, dimension, identifier, action)
	return args.Error(0)
}
func (m *MockRateLimiter) GetCurrentUsage(ctx context.Context, dimension domainservice.RateLimitDimension, identifier, action string) (int, int, time.Time, error) {
	args := m.Called(ctx, dimension, identifier, action)
	return args.Int(0), args.Int(1), args.Get(2).(time.Time), args.Error(3)
}
func (m *MockRateLimiter) SetCustomLimit(ctx context.Context, dimension domainservice.RateLimitDimension, identifier, action string, limit int, window, ttl int64) error {
	args := m.Called(ctx, dimension, identifier, action, limit, window, ttl)
	return args.Error(0)
}
func (m *MockRateLimiter) GetLimitConfig(ctx context.Context, dimension domainservice.RateLimitDimension, action string) (*domainservice.RateLimitConfig, error) {
	args := m.Called(ctx, dimension, action)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domainservice.RateLimitConfig), args.Error(1)
}
func (m *MockRateLimiter) IncrementCounter(ctx context.Context, dimension domainservice.RateLimitDimension, identifier, action string, increment int) (int, error) {
	args := m.Called(ctx, dimension, identifier, action, increment)
	return args.Int(0), args.Error(1)
}
func (m *MockRateLimiter) DecayCounter(ctx context.Context, dimension domainservice.RateLimitDimension, identifier, action string) error {
	args := m.Called(ctx, dimension, identifier, action)
	return args.Error(0)
}

type MockBlacklistStore struct {
	mock.Mock
}

func (m *MockBlacklistStore) Revoke(ctx context.Context, tenantID, jti string, exp time.Time) error {
	args := m.Called(ctx, tenantID, jti, exp)
	return args.Error(0)
}

func (m *MockBlacklistStore) IsRevoked(ctx context.Context, tenantID, jti string) (bool, error) {
	args := m.Called(ctx, tenantID, jti)
	return args.Bool(0), args.Error(1)
}

type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) LogEvent(ctx context.Context, event models.AuditEvent) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

type MockRiskOracle struct {
	mock.Mock
}

func (m *MockRiskOracle) GetTenantRisk(ctx context.Context, tenantID, agentID string) (*models.TenantRiskProfile, error) {
	args := m.Called(ctx, tenantID, agentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TenantRiskProfile), args.Error(1)
}

type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) EvaluateTrustLevel(ctx context.Context, riskProfile *models.TenantRiskProfile) models.TrustLevel {
	args := m.Called(ctx, riskProfile)
	return args.Get(0).(models.TrustLevel)
}

func (m *MockPolicyEngine) CheckKeyGeneration(ctx context.Context, policy models.PolicyRequest) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func Test_AuthAppService_RefreshToken_Success(t *testing.T) {
	// Arrange
	mockTokenService := new(MockTokenDomainService)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTenantRepo := new(MockTenantRepo)
	mockRateLimiter := new(MockRateLimiter)
	mockBlacklist := new(MockBlacklistStore)
	mockAuditService := new(MockAuditService)
	log := logger.NewDefaultLogger()

	mockRiskOracle := new(MockRiskOracle)
	mockPolicyEngine := new(MockPolicyEngine)
	authService := NewAuthAppService(
		mockTokenService,
		mockDeviceRepo,
		mockTenantRepo,
		mockRateLimiter,
		mockBlacklist,
		mockAuditService,
		mockRiskOracle,
		mockPolicyEngine,
		log,
	)

	ctx := context.Background()
	req := &dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
		TenantID:     "tenant-1",
	}

	oldRefreshToken := &models.Token{
		JTI:       "old-jti",
		TenantID:  "tenant-1",
		DeviceID:  "device-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	newAccessToken := &models.Token{
		JTI:       "new-access-token",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	newRefreshToken := &models.Token{
		JTI: "new-refresh-token",
	}

	mockTokenService.On("VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID).Return(oldRefreshToken, nil)
	mockBlacklist.On("IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI).Return(false, nil)
	mockRateLimiter.On("Allow", ctx, domainservice.RateLimitDimension("agent"), fmt.Sprintf("agent:%s:refresh", oldRefreshToken.DeviceID), "refresh").Return(true, 0, time.Time{}, nil)
	mockDeviceRepo.On("FindByID", ctx, oldRefreshToken.DeviceID).Return(&models.Device{Status: constants.DeviceStatusActive}, nil)
	mockBlacklist.On("Revoke", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI, oldRefreshToken.ExpiresAt).Return(nil)
	mockRiskOracle.On("GetTenantRisk", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID).Return(&models.TenantRiskProfile{}, nil)
	mockPolicyEngine.On("EvaluateTrustLevel", ctx, &models.TenantRiskProfile{}).Return(models.TrustLevelHigh)
	mockTokenService.On("GenerateAccessToken", ctx, oldRefreshToken, mock.AnythingOfType("*time.Duration"), "agent:read agent:write", "high").Return(newAccessToken, nil)
	mockTokenService.On("IssueToken", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID, []string(nil)).Return(newRefreshToken, nil)
	mockDeviceRepo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil)
	mockAuditService.On("LogEvent", ctx, mock.AnythingOfType("models.AuditEvent")).Return(nil).Twice()

	// Act
	resp, err := authService.RefreshToken(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "new-refresh-token", resp.RefreshToken)

	mockTokenService.AssertCalled(t, "VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID)
	mockBlacklist.AssertCalled(t, "IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI)
	mockRateLimiter.AssertCalled(t, "Allow", ctx, domainservice.RateLimitDimension("agent"), fmt.Sprintf("agent:%s:refresh", oldRefreshToken.DeviceID), "refresh")
	mockDeviceRepo.AssertCalled(t, "FindByID", ctx, oldRefreshToken.DeviceID)
	mockBlacklist.AssertCalled(t, "Revoke", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI, oldRefreshToken.ExpiresAt)
	mockTokenService.AssertCalled(t, "GenerateAccessToken", ctx, oldRefreshToken, mock.AnythingOfType("*time.Duration"), "agent:read agent:write", "high")
	mockTokenService.AssertCalled(t, "IssueToken", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID, []string(nil))
	mockDeviceRepo.AssertCalled(t, "Update", ctx, mock.AnythingOfType("*models.Device"))
	mockAuditService.AssertNumberOfCalls(t, "LogEvent", 2)
}

func Test_AuthAppService_RefreshToken_ReplayAttack(t *testing.T) {
	// Arrange
	mockTokenService := new(MockTokenDomainService)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTenantRepo := new(MockTenantRepo)
	mockRateLimiter := new(MockRateLimiter)
	mockBlacklist := new(MockBlacklistStore)
	mockAuditService := new(MockAuditService)
	log := logger.NewDefaultLogger()

	authService := NewAuthAppService(
		mockTokenService,
		mockDeviceRepo,
		mockTenantRepo,
		mockRateLimiter,
		mockBlacklist,
		mockAuditService,
		nil,
		nil,
		log,
	)

	ctx := context.Background()
	req := &dto.RefreshTokenRequest{
		RefreshToken: "reused-refresh-token",
		TenantID:     "tenant-1",
	}

	oldRefreshToken := &models.Token{
		JTI:       "old-jti",
		TenantID:  "tenant-1",
		DeviceID:  "device-1",
		TokenType: constants.TokenTypeRefresh,
	}

	mockTokenService.On("VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID).Return(oldRefreshToken, nil)
	mockBlacklist.On("IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI).Return(true, nil)

	// Act
	resp, err := authService.RefreshToken(ctx, req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, errors.ErrTokenRevoked(string(oldRefreshToken.TokenType), oldRefreshToken.JTI), err)

	mockTokenService.AssertCalled(t, "VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID)
	mockBlacklist.AssertCalled(t, "IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI)
	mockBlacklist.AssertNotCalled(t, "Revoke")
	mockTokenService.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenService.AssertNotCalled(t, "IssueToken")
}

func Test_AuthAppService_RefreshToken_HighTrust(t *testing.T) {
	// Arrange
	mockTokenService := new(MockTokenDomainService)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTenantRepo := new(MockTenantRepo)
	mockRateLimiter := new(MockRateLimiter)
	mockBlacklist := new(MockBlacklistStore)
	mockAuditService := new(MockAuditService)
	mockRiskOracle := new(MockRiskOracle)
	mockPolicyEngine := new(MockPolicyEngine)
	log := logger.NewDefaultLogger()

	authService := NewAuthAppService(
		mockTokenService,
		mockDeviceRepo,
		mockTenantRepo,
		mockRateLimiter,
		mockBlacklist,
		mockAuditService,
		mockRiskOracle,
		mockPolicyEngine,
		log,
	)

	ctx := context.Background()
	req := &dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
		TenantID:     "tenant-1",
	}

	oldRefreshToken := &models.Token{
		JTI:       "old-jti",
		TenantID:  "tenant-1",
		DeviceID:  "device-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	newAccessToken := &models.Token{
		JTI:       "new-access-token",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	newRefreshToken := &models.Token{
		JTI: "new-refresh-token",
	}

	riskProfile := &models.TenantRiskProfile{}

	mockTokenService.On("VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID).Return(oldRefreshToken, nil)
	mockBlacklist.On("IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI).Return(false, nil)
	mockRateLimiter.On("Allow", ctx, domainservice.RateLimitDimension("agent"), fmt.Sprintf("agent:%s:refresh", oldRefreshToken.DeviceID), "refresh").Return(true, 0, time.Time{}, nil)
	mockDeviceRepo.On("FindByID", ctx, oldRefreshToken.DeviceID).Return(&models.Device{Status: constants.DeviceStatusActive}, nil)
	mockBlacklist.On("Revoke", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI, oldRefreshToken.ExpiresAt).Return(nil)
	mockRiskOracle.On("GetTenantRisk", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID).Return(riskProfile, nil)
	mockPolicyEngine.On("EvaluateTrustLevel", ctx, riskProfile).Return(models.TrustLevelHigh)
	mockTokenService.On("GenerateAccessToken", ctx, oldRefreshToken, mock.AnythingOfType("*time.Duration"), "agent:read agent:write", "high").Return(newAccessToken, nil)
	mockTokenService.On("IssueToken", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID, []string(nil)).Return(newRefreshToken, nil)
	mockDeviceRepo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil)
	mockAuditService.On("LogEvent", ctx, mock.AnythingOfType("models.AuditEvent")).Return(nil).Twice()

	// Act
	resp, err := authService.RefreshToken(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "new-refresh-token", resp.RefreshToken)
}

func Test_AuthAppService_RefreshToken_LowTrust(t *testing.T) {
	// Arrange
	mockTokenService := new(MockTokenDomainService)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTenantRepo := new(MockTenantRepo)
	mockRateLimiter := new(MockRateLimiter)
	mockBlacklist := new(MockBlacklistStore)
	mockAuditService := new(MockAuditService)
	mockRiskOracle := new(MockRiskOracle)
	mockPolicyEngine := new(MockPolicyEngine)
	log := logger.NewDefaultLogger()

	authService := NewAuthAppService(
		mockTokenService,
		mockDeviceRepo,
		mockTenantRepo,
		mockRateLimiter,
		mockBlacklist,
		mockAuditService,
		mockRiskOracle,
		mockPolicyEngine,
		log,
	)

	ctx := context.Background()
	req := &dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
		TenantID:     "tenant-1",
	}

	oldRefreshToken := &models.Token{
		JTI:       "old-jti",
		TenantID:  "tenant-1",
		DeviceID:  "device-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	newAccessToken := &models.Token{
		JTI:       "new-access-token",
		ExpiresAt: time.Now().Add(60 * time.Second),
	}
	newRefreshToken := &models.Token{
		JTI: "new-refresh-token",
	}

	riskProfile := &models.TenantRiskProfile{}

	mockTokenService.On("VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID).Return(oldRefreshToken, nil)
	mockBlacklist.On("IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI).Return(false, nil)
	mockRateLimiter.On("Allow", ctx, domainservice.RateLimitDimension("agent"), fmt.Sprintf("agent:%s:refresh", oldRefreshToken.DeviceID), "refresh").Return(true, 0, time.Time{}, nil)
	mockDeviceRepo.On("FindByID", ctx, oldRefreshToken.DeviceID).Return(&models.Device{Status: constants.DeviceStatusActive}, nil)
	mockBlacklist.On("Revoke", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI, oldRefreshToken.ExpiresAt).Return(nil)
	mockRiskOracle.On("GetTenantRisk", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID).Return(riskProfile, nil)
	mockPolicyEngine.On("EvaluateTrustLevel", ctx, riskProfile).Return(models.TrustLevelLow)
	mockTokenService.On("GenerateAccessToken", ctx, oldRefreshToken, mock.AnythingOfType("*time.Duration"), "agent:read", "low").Return(newAccessToken, nil)
	mockTokenService.On("IssueToken", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID, []string(nil)).Return(newRefreshToken, nil)
	mockDeviceRepo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil)
	mockAuditService.On("LogEvent", ctx, mock.AnythingOfType("models.AuditEvent")).Return(nil).Twice()

	// Act
	resp, err := authService.RefreshToken(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "new-refresh-token", resp.RefreshToken)
}

func Test_AuthAppService_RefreshToken_RiskOracleError(t *testing.T) {
	// Arrange
	mockTokenService := new(MockTokenDomainService)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTenantRepo := new(MockTenantRepo)
	mockRateLimiter := new(MockRateLimiter)
	mockBlacklist := new(MockBlacklistStore)
	mockAuditService := new(MockAuditService)
	mockRiskOracle := new(MockRiskOracle)
	mockPolicyEngine := new(MockPolicyEngine)
	log := logger.NewDefaultLogger()

	authService := NewAuthAppService(
		mockTokenService,
		mockDeviceRepo,
		mockTenantRepo,
		mockRateLimiter,
		mockBlacklist,
		mockAuditService,
		mockRiskOracle,
		mockPolicyEngine,
		log,
	)

	ctx := context.Background()
	req := &dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
		TenantID:     "tenant-1",
	}

	oldRefreshToken := &models.Token{
		JTI:       "old-jti",
		TenantID:  "tenant-1",
		DeviceID:  "device-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	newAccessToken := &models.Token{
		JTI:       "new-access-token",
		ExpiresAt: time.Now().Add(60 * time.Second),
	}
	newRefreshToken := &models.Token{
		JTI: "new-refresh-token",
	}

	mockTokenService.On("VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID).Return(oldRefreshToken, nil)
	mockBlacklist.On("IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI).Return(false, nil)
	mockRateLimiter.On("Allow", ctx, domainservice.RateLimitDimension("agent"), fmt.Sprintf("agent:%s:refresh", oldRefreshToken.DeviceID), "refresh").Return(true, 0, time.Time{}, nil)
	mockDeviceRepo.On("FindByID", ctx, oldRefreshToken.DeviceID).Return(&models.Device{Status: constants.DeviceStatusActive}, nil)
	mockBlacklist.On("Revoke", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI, oldRefreshToken.ExpiresAt).Return(nil)
	mockRiskOracle.On("GetTenantRisk", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID).Return(nil, assert.AnError)
	mockPolicyEngine.On("EvaluateTrustLevel", ctx, &models.TenantRiskProfile{AnomalyScore: 1.0}).Return(models.TrustLevelLow)
	mockTokenService.On("GenerateAccessToken", ctx, oldRefreshToken, mock.AnythingOfType("*time.Duration"), "agent:read", "low").Return(newAccessToken, nil)
	mockTokenService.On("IssueToken", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID, []string(nil)).Return(newRefreshToken, nil)
	mockDeviceRepo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil)
	mockAuditService.On("LogEvent", ctx, mock.AnythingOfType("models.AuditEvent")).Return(nil).Twice()

	// Act
	resp, err := authService.RefreshToken(ctx, req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "new-access-token", resp.AccessToken)
	assert.Equal(t, "new-refresh-token", resp.RefreshToken)
}
