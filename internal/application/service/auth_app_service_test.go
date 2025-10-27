// internal/application/service/auth_app_service_test.go
package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
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

func (m *MockDeviceRepo) GetDeviceMetrics(ctx context.Context, tenantID string) (*repository.DeviceMetrics, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.DeviceMetrics), args.Error(1)
}

type MockTokenDomainService struct {
	mock.Mock
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
func (m *MockTokenDomainService) GenerateAccessToken(ctx context.Context, refreshToken *models.Token, requestedScope []string) (*models.Token, error) {
	args := m.Called(ctx, refreshToken, requestedScope)
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

func TestAuthAppService_IssueToken(t *testing.T) {
	mockTenantRepo := new(MockTenantRepo)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTokenService := new(MockTokenDomainService)
	mockRateLimiter := new(MockRateLimiter)
	testLogger := logger.NewDefaultLogger()

	service := NewAuthAppService(
		mockTokenService,
		mockDeviceRepo,
		mockTenantRepo,
		mockRateLimiter,
		testLogger,
	)

	ctx := context.Background()
	tenantID := uuid.New().String()
	agentID := "test-device-001"
	fingerprint := "test-fingerprint-hash"

	tests := []struct {
		name      string
		setupMock func()
		req       *dto.IssueTokenRequest
		wantErr   bool
		errType   errors.CBCError
	}{
		{
			name: "Successfully issue token for existing device",
			setupMock: func() {
				tenant := &models.Tenant{
					TenantID:   tenantID,
					TenantName: "Test Tenant",
					Status:     constants.TenantStatusActive,
				}
				mockTenantRepo.On("FindByID", ctx, tenantID).Return(tenant, nil).Once()

				mockRateLimiter.On("Allow", ctx, domainservice.RateLimitDimension("agent"), fmt.Sprintf("agent:%s:issue", agentID), "issue").Return(true, 100, time.Now(), nil).Once()

				device := &models.Device{
					TenantID:          tenantID,
					Status:            constants.DeviceStatusActive,
					DeviceFingerprint: fingerprint,
				}
				mockDeviceRepo.On("FindByID", ctx, agentID).Return(device, nil).Once()

				refreshToken := &models.Token{JTI: "refresh_token", Scope: "offline_access"}
				accessToken := &models.Token{JTI: "access_token", Scope: "api:read", ExpiresAt: time.Now().Add(time.Hour)}
				mockTokenService.On("IssueTokenPair", ctx, tenantID, agentID, fingerprint, []string(nil), map[string]interface{}(nil)).
					Return(refreshToken, accessToken, nil).Once()

				mockDeviceRepo.On("Update", ctx, mock.AnythingOfType("*models.Device")).Return(nil).Once()
			},
			req: &dto.IssueTokenRequest{
				TenantID: tenantID,
				AgentID:  agentID,
			},
			wantErr: false,
		},
		{
			name: "Tenant not found",
			setupMock: func() {
				mockTenantRepo.On("FindByID", ctx, tenantID).
					Return(nil, errors.ErrTenantNotFound(tenantID)).Once()
			},
			req: &dto.IssueTokenRequest{
				TenantID: tenantID,
				AgentID:  agentID,
			},
			wantErr: true,
			errType: errors.NewError(constants.ErrCodeInvalidRequest, 0, "", ""),
		},
		{
			name: "Rate limit exceeded",
			setupMock: func() {
				tenant := &models.Tenant{
					TenantID:   tenantID,
					TenantName: "Test Tenant",
					Status:     constants.TenantStatusActive,
				}
				mockTenantRepo.On("FindByID", ctx, tenantID).Return(tenant, nil).Once()

				mockRateLimiter.On("Allow", ctx, domainservice.RateLimitDimension("agent"), fmt.Sprintf("agent:%s:issue", agentID), "issue").Return(false, 100, time.Now(), nil).Once()
			},
			req: &dto.IssueTokenRequest{
				TenantID: tenantID,
				AgentID:  agentID,
			},
			wantErr: true,
			errType: errors.NewError(errors.ErrCodeRateLimitExceeded, 0, "", ""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			result, err := service.IssueToken(ctx, tt.req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.errType != nil {
					assert.Equal(t, tt.errType.Code(), err.(errors.CBCError).Code())
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, "access_token", result.AccessToken)
				assert.Equal(t, "refresh_token", result.RefreshToken)
			}
		})
	}
}
