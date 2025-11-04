//go:build integration

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	appservice "github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/tests/fakes"
)

type AuditFlowE2ETestSuite struct {
	suite.Suite
	router            *gin.Engine
	mockTenantRepo    *MockTenantRepository
	mockTokenService  *MockTokenService
	mockDeviceRepo    *MockDeviceRepository
	fakeAuditProducer *fakes.FakeAuditProducer
}

func (suite *AuditFlowE2ETestSuite) SetupTest() {
	// Logger
	log := logger.NewNoopLogger()

	// Services
	suite.fakeAuditProducer = fakes.NewFakeAuditProducer(10)

	// Mocks
	suite.mockTokenService = new(MockTokenService)
	suite.mockDeviceRepo = new(MockDeviceRepository)
	suite.mockTenantRepo = new(MockTenantRepository)
	mockRateLimitSvc := new(MockRateLimitService)
	mockBlacklist := new(MockBlacklistStore)
	authAppService := appservice.NewAuthAppService(suite.mockTokenService, suite.mockDeviceRepo, suite.mockTenantRepo, mockRateLimitSvc, mockBlacklist, suite.fakeAuditProducer, log)

	// Metrics
	reg := prometheus.NewRegistry()
	metrics := monitoring.NewMetrics(reg)
	metricsAdapter := handlers.NewMetricsAdapter(metrics)

	// Handlers
	authHandler := handlers.NewAuthHandler(authAppService, nil, metricsAdapter, log)

	// Router
	suite.router = gin.Default()
	suite.router.POST("/api/v1/auth/register-device", authHandler.RegisterDevice)
}

func (suite *AuditFlowE2ETestSuite) TestAuditFlow() {
	// 1. Register a device
	reqBody := `{
		"client_id": "test-client",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion": "test-assertion",
		"grant_type": "client_credentials",
		"tenant_id": "e2e-tenant",
		"agent_id": "e2e-agent",
		"device_fingerprint": "e2e-fingerprint",
		"device_name": "E2E Test Device",
		"device_type": "desktop"
	}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/auth/register-device", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	// Mock the service calls
	suite.mockTokenService.On("ValidateClientAssertion", mock.Anything, "test-assertion").Return(&models.Claims{TenantID: "e2e-tenant"}, nil)
	suite.mockTenantRepo.On("FindByID", mock.Anything, "e2e-tenant").Return(&models.Tenant{TenantID: "e2e-tenant"}, nil)
	suite.mockDeviceRepo.On("FindByFingerprint", mock.Anything, "e2e-tenant", "e2e-fingerprint").Return(nil, nil)
	suite.mockDeviceRepo.On("Save", mock.Anything, mock.AnythingOfType("*models.Device")).Return(nil)
	suite.mockTokenService.On("IssueTokenPair", mock.Anything, "e2e-tenant", mock.Anything, "e2e-fingerprint", mock.Anything, mock.Anything).Return(&models.Token{}, &models.Token{}, nil)

	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusCreated, w.Code)

	// 2. Consume the audit message from the fake producer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	receivedEvent, err := suite.fakeAuditProducer.DrainOne(ctx, 2*time.Second)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), receivedEvent)
	assert.Equal(suite.T(), "device.register", receivedEvent.EventType)
	assert.Equal(suite.T(), "e2e-tenant", receivedEvent.TenantID)
}

func TestAuditFlowE2ETestSuite(t *testing.T) {
	suite.Run(t, new(AuditFlowE2ETestSuite))
}
