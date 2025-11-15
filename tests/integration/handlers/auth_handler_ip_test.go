//go:build integration

package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	servicemocks "github.com/turtacn/cbc/internal/domain/service/mocks"
	"github.com/turtacn/cbc/internal/infrastructure/audit"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/internal/infrastructure/policy"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/logger"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	assert.NoError(t, err)

	err = db.AutoMigrate(&models.Tenant{}, &models.Device{}, &models.Key{}, &models.AuditEvent{}, &models.TenantRiskProfile{})
	assert.NoError(t, err)

	return db
}

func Test_RefreshToken_E2E_Blocked_IP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := setupTestDB(t)
	log := logger.NewNoopLogger()

	// Repositories
	tenantRepo := postgres.NewTenantRepository(db, log)
	deviceRepo := postgres.NewDeviceRepository(db, log)
	riskRepo := postgres.NewRiskRepository(db, log)

	// Domain Services
	tokenService := &servicemocks.TokenService{}
	rateLimitService := &servicemocks.RateLimitService{}
	blacklist := &servicemocks.TokenBlacklistStore{}
	riskOracle := &servicemocks.RiskOracle{}
	metrics := &servicemocks.Metrics{}

	policyEngine, err := policy.NewStaticPolicyEngine("policies.yaml")
	assert.NoError(t, err)

	// Audit Service
	auditService := audit.NewGormAuditService(db)

	// App Services
	authService := service.NewAuthAppService(tokenService, deviceRepo, tenantRepo, rateLimitService, blacklist, auditService, riskOracle, policyEngine, log, metrics)
	deviceAuthAppService := service.NewDeviceAuthAppService(nil, nil, nil, &config.OAuthConfig{}, deviceRepo, tenantRepo, rateLimitService, auditService, log)
	handler := handlers.NewAuthHandler(authService, deviceAuthAppService, log)

	router := gin.Default()
	router.POST("/refresh", handler.RefreshToken)

	// Test Data
	tenant := models.NewTenant("test-tenant", "Test Tenant")
	err = tenantRepo.Save(context.Background(), tenant)
	assert.NoError(t, err)

	device := &models.Device{
		DeviceID: "test-device",
		TenantID: tenant.TenantID,
		Status:   constants.DeviceStatusActive,
	}
	err = deviceRepo.Save(context.Background(), device)
	assert.NoError(t, err)

	riskProfile := &models.TenantRiskProfile{
		TenantID:   tenant.TenantID,
		BlockedIPs: []string{"127.0.0.1"},
	}
	err = riskRepo.UpsertTenantRiskProfile(context.Background(), riskProfile)
	assert.NoError(t, err)

	oldRefreshToken := &models.Token{
		JTI:       "old-refresh-token",
		TenantID:  tenant.TenantID,
		DeviceID:  device.DeviceID,
		TokenType: constants.TokenTypeRefresh,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	newAccessToken := &models.Token{
		JTI:       "new-access-token",
		Scope:     "agent:read",
		ExpiresAt: time.Now().Add(60 * time.Second),
	}

	newRefreshToken := &models.Token{
		JTI: "new-refresh-token",
	}

	// Mock setups
	tokenService.On("VerifyToken", mock.Anything, "old-refresh-token", constants.TokenTypeRefresh, tenant.TenantID).Return(oldRefreshToken, nil)
	blacklist.On("IsRevoked", mock.Anything, tenant.TenantID, "old-refresh-token").Return(false, nil)
	rateLimitService.On("Allow", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, 0, time.Time{}, nil)
	blacklist.On("Revoke", mock.Anything, tenant.TenantID, "old-refresh-token", oldRefreshToken.ExpiresAt).Return(nil)
	riskOracle.On("GetTenantRisk", mock.Anything, tenant.TenantID, device.DeviceID).Return(riskProfile, nil)
	tokenService.On("GenerateAccessToken", mock.Anything, oldRefreshToken, mock.Anything, "agent:read", "low").Return(newAccessToken, nil)
	tokenService.On("IssueToken", mock.Anything, tenant.TenantID, device.DeviceID, mock.Anything).Return(newRefreshToken, nil)
	metrics.On("RecordTokenIssueByTrust", "low_trust", tenant.TenantID).Return()

	// Request
	reqBody := &dto.TokenRefreshRequest{
		RefreshToken: "old-refresh-token",
		TenantID:     tenant.TenantID,
	}
	jsonBody, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/refresh", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	// Assertions
	assert.Equal(t, http.StatusOK, rr.Code)

	var respBody dto.TokenResponse
	err = json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token", respBody.AccessToken)
	assert.Equal(t, "new-refresh-token", respBody.RefreshToken)
	assert.InDelta(t, 60, respBody.ExpiresIn, 1) // check if expires in is around 60 seconds
	assert.Equal(t, "agent:read", respBody.Scope)

	// Verify Audit Log
	var auditEvent models.AuditEvent
	err = db.First(&auditEvent, "event_type = ?", "token.refresh").Error
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1", auditEvent.Metadata["ip"])
	assert.Equal(t, "low", auditEvent.Metadata["trust_level"])
}
