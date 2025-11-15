
// internal/application/service/auth_app_service_observability_test.go
package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	domainservice "github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/logger"
)

type MockMetrics struct {
	mock.Mock
}

func (m *MockMetrics) RecordTokenIssue(tenantID, grantType string, success bool, duration time.Duration, errorCode string) {
	m.Called(tenantID, grantType, success, duration, errorCode)
}

func (m *MockMetrics) RecordTokenIssueByTrust(trustLevel, tenantID string) {
	m.Called(trustLevel, tenantID)
}

func (m *MockMetrics) RecordTokenVerify(tenantID string, success bool, errorCode string) {
	m.Called(tenantID, success, errorCode)
}

func (m *MockMetrics) RecordTokenRevoke(tenantID, reason string) {
	m.Called(tenantID, reason)
}

func (m *MockMetrics) RecordDeviceRegister(tenantID string, success bool, errorCode string) {
	m.Called(tenantID, success, errorCode)
}

func (m *MockMetrics) RecordRateLimitHit(tenantID, scope string) {
	m.Called(tenantID, scope)
}

func (m *MockMetrics) RecordCacheAccess(cacheType string, hit bool) {
	m.Called(cacheType, hit)
}

func (m *MockMetrics) RecordDBQuery(operation string, duration time.Duration) {
	m.Called(operation, duration)
}

func (m *MockMetrics) UpdateDBConnections(active, idle int) {
	m.Called(active, idle)
}

func (m *MockMetrics) RecordVaultAPI(operation string, duration time.Duration, err error) {
	m.Called(operation, duration, err)
}

func (m *MockMetrics) UpdateGoroutineCount(count int) {
	m.Called(count)
}

func Test_AuthAppService_RefreshToken_Observability(t *testing.T) {
	// Arrange
	mockTokenService := new(MockTokenDomainService)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTenantRepo := new(MockTenantRepo)
	mockRateLimiter := new(MockRateLimiter)
	mockBlacklist := new(MockBlacklistStore)
	mockAuditService := new(MockAuditService)
	mockRiskOracle := new(MockRiskOracle)
	mockPolicyEngine := new(MockPolicyEngine)
	mockMetrics := new(MockMetrics)
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
		mockMetrics,
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

	// Setup mock expectations
	mockTokenService.On("VerifyToken", ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID).Return(oldRefreshToken, nil)
	mockBlacklist.On("IsRevoked", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI).Return(false, nil)
	mockRateLimiter.On("Allow", ctx, domainservice.RateLimitDimension("agent"), mock.Anything, "refresh").Return(true, 0, time.Time{}, nil)
	mockDeviceRepo.On("FindByID", ctx, oldRefreshToken.DeviceID).Return(&models.Device{Status: constants.DeviceStatusActive}, nil)
	mockBlacklist.On("Revoke", ctx, oldRefreshToken.TenantID, oldRefreshToken.JTI, oldRefreshToken.ExpiresAt).Return(nil)
	mockRiskOracle.On("GetTenantRisk", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID).Return(riskProfile, nil)
	mockPolicyEngine.On("EvaluateTrustLevel", ctx, riskProfile).Return(models.TrustLevelLow)
	mockTokenService.On("GenerateAccessToken", ctx, oldRefreshToken, mock.AnythingOfType("*time.Duration"), "agent:read", "low").Return(newAccessToken, nil)
	mockTokenService.On("IssueToken", ctx, oldRefreshToken.TenantID, oldRefreshToken.DeviceID, []string(nil)).Return(newRefreshToken, nil)
	mockDeviceRepo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil)
	mockAuditService.On("LogEvent", ctx, mock.AnythingOfType("models.AuditEvent")).Return(nil).Twice()

	// Expectations for observability
	mockMetrics.On("RecordTokenIssueByTrust", "low_trust", "tenant-1").Return()

	// Act
	_, err := authService.RefreshToken(ctx, req)

	// Assert
	assert.NoError(t, err)

	// Verify that the observability methods were called
	mockMetrics.AssertCalled(t, "RecordTokenIssueByTrust", "low_trust", "tenant-1")
}
