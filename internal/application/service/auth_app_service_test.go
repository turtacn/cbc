package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	appdto "github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// --- Mocks ---
type MockTenantRepo struct{ mock.Mock }

func (m *MockTenantRepo) FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, *errors.AppError) {
	args := m.Called(ctx, id)
	var t *models.Tenant
	if args.Get(0) != nil {
		t = args.Get(0).(*models.Tenant)
	}
	var e *errors.AppError
	if args.Get(1) != nil {
		e = args.Get(1).(*errors.AppError)
	}
	return t, e
}
func (m *MockTenantRepo) FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, *errors.AppError) {
	return nil, nil
}
func (m *MockTenantRepo) UpdateConfig(ctx context.Context, tenant *models.Tenant) *errors.AppError {
	return nil
}
func (m *MockTenantRepo) Save(ctx context.Context, tenant *models.Tenant) *errors.AppError {
	return nil
}

type MockDeviceRepo struct{ mock.Mock }

func (m *MockDeviceRepo) FindByID(ctx context.Context, id uuid.UUID) (*models.Device, *errors.AppError) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, nil
	}
	return args.Get(0).(*models.Device), nil
}
func (m *MockDeviceRepo) FindByDeviceID(ctx context.Context, tenantID uuid.UUID, deviceID string) (*models.Device, *errors.AppError) {
	args := m.Called(ctx, tenantID, deviceID)
	if args.Get(0) == nil {
		return nil, nil
	}
	return args.Get(0).(*models.Device), nil
}
func (m *MockDeviceRepo) FindByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Device, *errors.AppError) {
	args := m.Called(ctx, tenantID, limit, offset)
	if args.Get(0) == nil {
		return nil, nil
	}
	return args.Get(0).([]*models.Device), nil
}

func (m *MockDeviceRepo) UpdateLastSeen(ctx context.Context, id uuid.UUID, lastSeenAt time.Time) *errors.AppError {
	return nil
}

func (m *MockDeviceRepo) Save(ctx context.Context, d *models.Device) *errors.AppError { return nil }

type MockTokenSvc struct{ mock.Mock }

func (m *MockTokenSvc) IssueTokenPair(ctx context.Context, tenant *models.Tenant, device *models.Device) (*models.Token, *models.Token, *errors.AppError) {
	args := m.Called(ctx, tenant, device)
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), nil
}
func (m *MockTokenSvc) RefreshToken(ctx context.Context, oldRefreshTokenString string) (*models.Token, *models.Token, *errors.AppError) {
	return nil, nil, nil
}
func (m *MockTokenSvc) VerifyToken(ctx context.Context, tokenString string) (*models.Token, *errors.AppError) {
	return nil, nil
}
func (m *MockTokenSvc) RevokeToken(ctx context.Context, jti string) *errors.AppError { return nil }

type MockRateLimiter struct{ mock.Mock }

func (m *MockRateLimiter) Allow(ctx context.Context, scope constants.RateLimitScope, identifier string) (bool, *errors.AppError) {
	args := m.Called(ctx, scope, identifier)
	return args.Bool(0), nil
}
func (m *MockRateLimiter) ResetLimit(ctx context.Context, scope constants.RateLimitScope, identifier string) *errors.AppError {
	return nil
}
func (m *MockRateLimiter) GetCurrentUsage(ctx context.Context, scope constants.RateLimitScope, identifier string) (int, *errors.AppError) {
	return 0, nil
}

// --- minimal helper token impl for tests ---
func newTestToken(jti string, expiresInSec int64) *models.Token {
	return &models.Token{
		JTI: jti,
		// below functions referenced in service: implement methods in models.Token to return values
		// to keep unit test simple, use small struct fields; in real code adjust accordingly.
		ExpiresAt: time.Now().Add(time.Duration(expiresInSec) * time.Second),
	}
}

// --- Test ---
func TestIssueToken_HappyPath(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New()

	mockTenant := &models.Tenant{ID: tenantID, Status: "active"}
	mockTenantRepo := &MockTenantRepo{}
	mockTenantRepo.On("FindByID", mock.Anything, tenantID).Return(mockTenant, nil)

	mockDeviceRepo := &MockDeviceRepo{}
	mockTokenSvc := &MockTokenSvc{}
	access := newTestToken("jti-access", 3600)
	refresh := newTestToken("jti-refresh", 7*24*3600)
	mockTokenSvc.On("IssueTokenPair", mock.Anything, mockTenant, mock.Anything).Return(access, refresh, nil)

	mockRL := &MockRateLimiter{}
	// rate limiter allow
	mockRL.On("Allow", mock.Anything, mock.Anything, mock.Anything).Return(true, nil)

	// construct app service (use a no-op logger)
	l := logger.NewNoopLogger() // if not exists, you can pass nil or construct basic logger
	appSvc := service.NewAuthAppService(mockTenantRepo, mockDeviceRepo, mockTokenSvc, mockRL, l)

	req := &appdto.TokenIssueRequest{
		GrantType: "client_credentials",
		TenantID:  tenantID,
		DeviceID:  "device-123",
	}

	resp, err := appSvc.IssueToken(ctx, req)
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}
