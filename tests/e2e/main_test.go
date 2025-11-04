//go:build integration

package e2e

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
)

// MockTokenService is a mock implementation of domain.TokenService
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) IssueToken(ctx context.Context, tenantID, subject string, scope []string) (*models.Token, error) {
	args := m.Called(ctx, tenantID, subject, scope)
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenService) ValidateClientAssertion(ctx context.Context, clientAssertion string) (*models.Claims, error) {
	args := m.Called(ctx, clientAssertion)
	return args.Get(0).(*models.Claims), args.Error(1)
}

func (m *MockTokenService) IssueTokenPair(ctx context.Context, tenantID, agentID, deviceFingerprint string, scope []string, metadata map[string]interface{}) (*models.Token, *models.Token, error) {
	args := m.Called(ctx, tenantID, agentID, deviceFingerprint, scope, metadata)
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), args.Error(2)
}

func (m *MockTokenService) RefreshToken(ctx context.Context, refreshTokenString string, requestedScope []string) (*models.Token, *models.Token, error) {
	args := m.Called(ctx, refreshTokenString, requestedScope)
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), args.Error(2)
}

func (m *MockTokenService) VerifyToken(ctx context.Context, tokenString string, tokenType constants.TokenType, tenantID string) (*models.Token, error) {
	args := m.Called(ctx, tokenString, tokenType, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenService) RevokeToken(ctx context.Context, jti, tenantID, reason string) error {
	args := m.Called(ctx, jti, tenantID, reason)
	return args.Error(0)
}

func (m *MockTokenService) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	args := m.Called(ctx, jti)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenService) GenerateAccessToken(ctx context.Context, refreshToken *models.Token, requestedScope []string) (*models.Token, error) {
	args := m.Called(ctx, refreshToken, requestedScope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenService) ValidateTokenClaims(ctx context.Context, token *models.Token, validationContext map[string]interface{}) (bool, error) {
	args := m.Called(ctx, token, validationContext)
	return args.Bool(0), args.Error(1)
}

func (m *MockTokenService) IntrospectToken(ctx context.Context, tokenString, tokenTypeHint string) (*models.TokenIntrospection, error) {
	args := m.Called(ctx, tokenString, tokenTypeHint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenIntrospection), args.Error(1)
}

func (m *MockTokenService) CleanupExpiredTokens(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return int64(args.Int(0)), args.Error(1)
}

// MockTokenRepository is a mock implementation of repository.TokenRepository
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) Save(ctx context.Context, token *models.Token) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *MockTokenRepository) SaveBatch(ctx context.Context, tokens []*models.Token) error {
	args := m.Called(ctx, tokens)
	return args.Error(0)
}
func (m *MockTokenRepository) FindByJTI(ctx context.Context, jti string) (*models.Token, error) {
	args := m.Called(ctx, jti)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}
func (m *MockTokenRepository) FindByAgentID(ctx context.Context, agentID string) ([]*models.Token, error) {
	args := m.Called(ctx, agentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Token), args.Error(1)
}
func (m *MockTokenRepository) FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Token, int64, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*models.Token), int64(args.Int(1)), args.Error(2)
}
func (m *MockTokenRepository) FindActiveByAgentID(ctx context.Context, agentID string) ([]*models.Token, error) {
	args := m.Called(ctx, agentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Token), args.Error(1)
}
func (m *MockTokenRepository) Revoke(ctx context.Context, jti string, reason string) error {
	args := m.Called(ctx, jti, reason)
	return args.Error(0)
}
func (m *MockTokenRepository) RevokeByAgentID(ctx context.Context, agentID string, reason string) (int64, error) {
	args := m.Called(ctx, agentID, reason)
	return int64(args.Int(0)), args.Error(1)
}
func (m *MockTokenRepository) RevokeByTenantID(ctx context.Context, tenantID string, reason string) (int64, error) {
	args := m.Called(ctx, tenantID, reason)
	return int64(args.Int(0)), args.Error(1)
}
func (m *MockTokenRepository) IsRevoked(ctx context.Context, jti string) (bool, error) {
	args := m.Called(ctx, jti)
	return args.Bool(0), args.Error(1)
}
func (m *MockTokenRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return int64(args.Int(0)), args.Error(1)
}
func (m *MockTokenRepository) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	args := m.Called(ctx, tenantID)
	return int64(args.Int(0)), args.Error(1)
}
func (m *MockTokenRepository) CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error) {
	args := m.Called(ctx, tenantID)
	return int64(args.Int(0)), args.Error(1)
}
func (m *MockTokenRepository) UpdateLastUsedAt(ctx context.Context, jti string, lastUsedAt time.Time) error {
	args := m.Called(ctx, jti, lastUsedAt)
	return args.Error(0)
}

// MockDeviceRepository is a mock implementation of repository.DeviceRepository
type MockDeviceRepository struct {
	mock.Mock
}

func (m *MockDeviceRepository) Save(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockDeviceRepository) Update(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *MockDeviceRepository) FindByID(ctx context.Context, agentID string) (*models.Device, error) {
	args := m.Called(ctx, agentID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

func (m *MockDeviceRepository) FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Device, int64, error) {
	args := m.Called(ctx, tenantID, limit, offset)
	return args.Get(0).([]*models.Device), int64(args.Int(1)), args.Error(2)
}

func (m *MockDeviceRepository) FindByFingerprint(ctx context.Context, tenantID, fingerprint string) (*models.Device, error) {
	args := m.Called(ctx, tenantID, fingerprint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

func (m *MockDeviceRepository) Exists(ctx context.Context, agentID string) (bool, error) {
	args := m.Called(ctx, agentID)
	return args.Bool(0), args.Error(1)
}

func (m *MockDeviceRepository) UpdateLastSeen(ctx context.Context, agentID string, lastSeenAt time.Time) error {
	args := m.Called(ctx, agentID, lastSeenAt)
	return args.Error(0)
}

func (m *MockDeviceRepository) UpdateTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error {
	args := m.Called(ctx, agentID, trustLevel)
	return args.Error(0)
}

func (m *MockDeviceRepository) UpdateStatus(ctx context.Context, agentID string, status constants.DeviceStatus) error {
	args := m.Called(ctx, agentID, status)
	return args.Error(0)
}

func (m *MockDeviceRepository) Delete(ctx context.Context, agentID string) error {
	args := m.Called(ctx, agentID)
	return args.Error(0)
}

func (m *MockDeviceRepository) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	args := m.Called(ctx, tenantID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockDeviceRepository) CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error) {
	args := m.Called(ctx, tenantID)
	return int64(args.Int(0)), args.Error(1)
}

func (m *MockDeviceRepository) FindInactiveDevices(ctx context.Context, inactiveSince time.Time, limit, offset int) ([]*models.Device, int64, error) {
	args := m.Called(ctx, inactiveSince, limit, offset)
	return args.Get(0).([]*models.Device), int64(args.Int(1)), args.Error(2)
}

func (m *MockDeviceRepository) FindByTrustLevel(ctx context.Context, tenantID string, trustLevel constants.TrustLevel, limit, offset int) ([]*models.Device, int64, error) {
	args := m.Called(ctx, tenantID, trustLevel, limit, offset)
	return args.Get(0).([]*models.Device), int64(args.Int(1)), args.Error(2)
}

func (m *MockDeviceRepository) BatchUpdateLastSeen(ctx context.Context, updates map[string]time.Time) error {
	args := m.Called(ctx, updates)
	return args.Error(0)
}

// MockTenantRepository is a mock implementation of repository.TenantRepository
type MockTenantRepository struct {
	mock.Mock
}

func (m *MockTenantRepository) Save(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockTenantRepository) Update(ctx context.Context, tenant *models.Tenant) error {
	args := m.Called(ctx, tenant)
	return args.Error(0)
}

func (m *MockTenantRepository) FindByID(ctx context.Context, tenantID string) (*models.Tenant, error) {
	args := m.Called(ctx, tenantID)
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepository) FindByName(ctx context.Context, name string) (*models.Tenant, error) {
	args := m.Called(ctx, name)
	return args.Get(0).(*models.Tenant), args.Error(1)
}

func (m *MockTenantRepository) FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, int64, error) {
	args := m.Called(ctx, limit, offset)
	return args.Get(0).([]*models.Tenant), int64(args.Int(1)), args.Error(2)
}

func (m *MockTenantRepository) FindActiveAll(ctx context.Context) ([]*models.Tenant, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*models.Tenant), args.Error(1)
}

func (m *MockTenantRepository) Exists(ctx context.Context, tenantID string) (bool, error) {
	args := m.Called(ctx, tenantID)
	return args.Bool(0), args.Error(1)
}

func (m *MockTenantRepository) UpdateStatus(ctx context.Context, tenantID string, status constants.TenantStatus) error {
	args := m.Called(ctx, tenantID, status)
	return args.Error(0)
}

func (m *MockTenantRepository) UpdateRateLimitConfig(ctx context.Context, tenantID string, config *models.RateLimitConfig) error {
	args := m.Called(ctx, tenantID, config)
	return args.Error(0)
}

func (m *MockTenantRepository) UpdateTokenTTLConfig(ctx context.Context, tenantID string, config *models.TokenTTLConfig) error {
	args := m.Called(ctx, tenantID, config)
	return args.Error(0)
}

func (m *MockTenantRepository) UpdateKeyRotationPolicy(ctx context.Context, tenantID string, policy *models.KeyRotationPolicy) error {
	args := m.Called(ctx, tenantID, policy)
	return args.Error(0)
}

func (m *MockTenantRepository) Delete(ctx context.Context, tenantID string) error {
	args := m.Called(ctx, tenantID)
	return args.Error(0)
}

func (m *MockTenantRepository) GetTenantMetrics(ctx context.Context, tenantID string) (*repository.TenantMetrics, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.TenantMetrics), args.Error(1)
}

func (m *MockTenantRepository) GetAllMetrics(ctx context.Context) (*repository.SystemMetrics, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.SystemMetrics), args.Error(1)
}

func (m *MockTenantRepository) IncrementRequestCount(ctx context.Context, tenantID string, count int64) error {
	args := m.Called(ctx, tenantID, count)
	return args.Error(0)
}

func (m *MockTenantRepository) UpdateLastActivityAt(ctx context.Context, tenantID string, lastActivityAt time.Time) error {
	args := m.Called(ctx, tenantID, lastActivityAt)
	return args.Error(0)
}

// MockRateLimitService is a mock implementation of domain.RateLimitService
type MockRateLimitService struct {
	mock.Mock
}

func (m *MockRateLimitService) Allow(ctx context.Context, dimension service.RateLimitDimension, key, action string) (bool, int, time.Time, error) {
	args := m.Called(ctx, dimension, key, action)
	return args.Bool(0), args.Int(1), args.Get(2).(time.Time), args.Error(3)
}

// MockAuditService is a mock implementation of domain.AuditService
type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) LogEvent(ctx context.Context, event models.AuditEvent) error {
	args := m.Called(ctx, event)
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
