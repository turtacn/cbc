// internal/application/service/auth_app_service_test.go
package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
)

// Mock implementations for dependencies
type MockTenantRepo struct {
	mock.Mock
}

func (m *MockTenantRepo) FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepo) Create(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockTenantRepo) Update(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

type MockDeviceRepo struct {
	mock.Mock
}

func (m *MockDeviceRepo) FindByDeviceID(ctx context.Context, tenantID uuid.UUID, deviceID string) (*models.Device, error) {
	args := m.Called(ctx, tenantID, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

func (m *MockDeviceRepo) Create(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockDeviceRepo) Update(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

type MockTokenDomainService struct {
	mock.Mock
}

func (m *MockTokenDomainService) CreateToken(ctx context.Context, tenantID, deviceID uuid.UUID, jti, tokenType, scope string, ttl time.Duration) (*models.Token, error) {
	args := m.Called(ctx, tenantID, deviceID, jti, tokenType, scope, ttl)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenDomainService) ValidateToken(ctx context.Context, jti string) (*models.Token, error) {
	args := m.Called(ctx, jti)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenDomainService) RevokeToken(ctx context.Context, jti, reason string) error {
	args := m.Called(ctx, jti, reason)
	return args.Error(0)
}

func (m *MockTokenDomainService) RevokeDeviceTokens(ctx context.Context, tenantID, deviceID uuid.UUID, reason string) error {
	args := m.Called(ctx, tenantID, deviceID, reason)
	return args.Error(0)
}

type MockJWTManager struct {
	mock.Mock
}

func (m *MockJWTManager) IssueToken(ctx context.Context, token *models.Token) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func (m *MockJWTManager) ValidateToken(ctx context.Context, tokenString string) (*models.Token, error) {
	args := m.Called(ctx, tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockJWTManager) RefreshPublicKeys(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type MockRateLimiter struct {
	mock.Mock
}

func (m *MockRateLimiter) Allow(ctx context.Context, key string, limit, window int) (bool, error) {
	args := m.Called(ctx, key, limit, window)
	return args.Bool(0), args.Error(1)
}

func (m *MockRateLimiter) Reset(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) Log(ctx context.Context, log *models.AuditLog) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func TestAuthAppService_IssueToken(t *testing.T) {
	mockTenantRepo := new(MockTenantRepo)
	mockDeviceRepo := new(MockDeviceRepo)
	mockTokenService := new(MockTokenDomainService)
	mockJWTManager := new(MockJWTManager)
	mockRateLimiter := new(MockRateLimiter)
	mockAuditLogger := new(MockAuditLogger)

	service := NewAuthAppService(
		mockTenantRepo,
		mockDeviceRepo,
		mockTokenService,
		mockJWTManager,
		mockRateLimiter,
		mockAuditLogger,
	)

	ctx := context.Background()
	tenantID := uuid.New()
	deviceID := "test-device-001"
	deviceType := models.DeviceTypeMobile
	fingerprint := "test-fingerprint-hash"
	scope := "agent:read agent:write"

	tests := []struct {
		name      string
		setupMock func()
		wantErr   bool
		errType   error
	}{
		{
			name: "Successfully issue token for new device",
			setupMock: func() {
				tenant := &models.Tenant{
					ID:                tenantID,
					Name:              "Test Tenant",
					Status:            models.TenantStatusActive,
					AccessTokenTTL:    900,
					RefreshTokenTTL:   2592000,
					RateLimitConfig:   map[string]interface{}{"device": 100},
				}
				mockTenantRepo.On("FindByID", ctx, tenantID).Return(tenant, nil).Once()

				mockDeviceRepo.On("FindByDeviceID", ctx, tenantID, deviceID).
					Return(nil, errors.ErrDeviceNotFound).Once()

				mockDeviceRepo.On("Create", ctx, mock.MatchedBy(func(device *models.Device) bool {
					return device.DeviceID == deviceID && device.TenantID == tenantID
				})).Return(nil).Once()

				mockRateLimiter.On("Allow", ctx, mock.Anything, 100, 3600).Return(true, nil).Once()

				accessToken := &models.Token{
					ID:        uuid.New(),
					JTI:       uuid.New().String(),
					TenantID:  tenantID,
					TokenType: models.TokenTypeAccess,
					Scope:     scope,
					IssuedAt:  time.Now(),
					ExpiresAt: time.Now().Add(900 * time.Second),
				}
				mockTokenService.On("CreateToken", ctx, tenantID, mock.Anything, mock.Anything,
					models.TokenTypeAccess, scope, time.Duration(900)*time.Second).
					Return(accessToken, nil).Once()

				refreshToken := &models.Token{
					ID:        uuid.New(),
					JTI:       uuid.New().String(),
					TenantID:  tenantID,
					TokenType: models.TokenTypeRefresh,
					Scope:     scope,
					IssuedAt:  time.Now(),
					ExpiresAt: time.Now().Add(2592000 * time.Second),
				}
				mockTokenService.On("CreateToken", ctx, tenantID, mock.Anything, mock.Anything,
					models.TokenTypeRefresh, scope, time.Duration(2592000)*time.Second).
					Return(refreshToken, nil).Once()

				mockJWTManager.On("IssueToken", ctx, accessToken).Return("jwt.access.token", nil).Once()
				mockJWTManager.On("IssueToken", ctx, refreshToken).Return("jwt.refresh.token", nil).Once()

				mockAuditLogger.On("Log", ctx, mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Tenant not found",
			setupMock: func() {
				mockTenantRepo.On("FindByID", ctx, tenantID).
					Return(nil, errors.ErrTenantNotFound).Once()
			},
			wantErr: true,
			errType: errors.ErrTenantNotFound,
		},
		{
			name: "Rate limit exceeded",
			setupMock: func() {
				tenant := &models.Tenant{
					ID:                tenantID,
					Name:              "Test Tenant",
					Status:            models.TenantStatusActive,
					AccessTokenTTL:    900,
					RefreshTokenTTL:   2592000,
					RateLimitConfig:   map[string]interface{}{"device": 100},
				}
				mockTenantRepo.On("FindByID", ctx, tenantID).Return(tenant, nil).Once()

				device := &models.Device{
					ID:         uuid.New(),
					TenantID:   tenantID,
					DeviceID:   deviceID,
					DeviceType: deviceType,
					Fingerprint: fingerprint,
				}
				mockDeviceRepo.On("FindByDeviceID", ctx, tenantID, deviceID).Return(device, nil).Once()

				mockRateLimiter.On("Allow", ctx, mock.Anything, 100, 3600).Return(false, nil).Once()

				mockAuditLogger.On("Log", ctx, mock.Anything).Return(nil).Once()
			},
			wantErr: true,
			errType: errors.ErrRateLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			result, err := service.IssueToken(ctx, tenantID, deviceID, deviceType, fingerprint, scope)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.AccessToken)
				assert.NotEmpty(t, result.RefreshToken)
				assert.Greater(t, result.ExpiresIn, int64(0))
			}

			mockTenantRepo.AssertExpectations(t)
			mockDeviceRepo.AssertExpectations(t)
			mockTokenService.AssertExpectations(t)
			mockJWTManager.AssertExpectations(t)
			mockRateLimiter.AssertExpectations(t)
			mockAuditLogger.AssertExpectations(t)
		})
	}
}

//Personal.AI order the ending
