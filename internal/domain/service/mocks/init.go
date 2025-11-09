package mocks

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/pkg/constants"
)

type MockHTTPMetrics struct {
	mock.Mock
}

func (m *MockHTTPMetrics) RecordRequestStart(ctx context.Context, endpoint string) {
	m.Called(ctx, endpoint)
}

func (m *MockHTTPMetrics) RecordRequestDuration(ctx context.Context, endpoint string, statusCode int, duration time.Duration) {
	m.Called(ctx, endpoint, statusCode, duration)
}

func (m *MockHTTPMetrics) RecordRequestError(ctx context.Context, endpoint string, status int) {
	m.Called(ctx, endpoint, status)
}

type MockAuthAppService struct {
	mock.Mock
}

func (m *MockAuthAppService) IssueToken(ctx context.Context, req *dto.TokenIssueRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

func (m *MockAuthAppService) RefreshToken(ctx context.Context, req *dto.TokenRefreshRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

func (m *MockAuthAppService) RevokeToken(ctx context.Context, req *dto.TokenRevokeRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthAppService) IntrospectToken(ctx context.Context, token string) (*dto.TokenIntrospectionResponse, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenIntrospectionResponse), args.Error(1)
}

func (m *MockAuthAppService) RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

type MockDeviceAppService struct {
	mock.Mock
}

func (m *MockDeviceAppService) RegisterDevice(ctx context.Context, req *dto.DeviceRegisterRequest) (*dto.DeviceResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.DeviceResponse), args.Error(1)
}

func (m *MockDeviceAppService) GetDeviceInfo(ctx context.Context, deviceID string) (*dto.DeviceResponse, error) {
	args := m.Called(ctx, deviceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.DeviceResponse), args.Error(1)
}

func (m *MockDeviceAppService) UpdateDeviceInfo(ctx context.Context, deviceID string, req *dto.DeviceUpdateRequest) (*dto.DeviceResponse, error) {
	args := m.Called(ctx, deviceID, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.DeviceResponse), args.Error(1)
}

func (m *MockDeviceAppService) DeactivateDevice(ctx context.Context, agentID string, reason string) error {
	args := m.Called(ctx, agentID, reason)
	return args.Error(0)
}

func (m *MockDeviceAppService) UpdateDeviceTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error {
	args := m.Called(ctx, agentID, trustLevel)
	return args.Error(0)
}

func (m *MockDeviceAppService) ListDevicesByTenant(ctx context.Context, tenantID string, page, pageSize int) ([]*dto.DeviceResponse, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*dto.DeviceResponse), int64(args.Int(1)), args.Error(2)
}

func (m *MockDeviceAppService) VerifyDeviceFingerprint(ctx context.Context, agentID, fingerprint string) (bool, error) {
	args := m.Called(ctx, agentID, fingerprint)
	return args.Bool(0), args.Error(1)
}

type MockRedisConnectionManager struct {
	mock.Mock
}

func (m *MockRedisConnectionManager) GetClient() redis.UniversalClient {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(redis.UniversalClient)
}

func (m *MockRedisConnectionManager) Ping(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockRedisConnectionManager) HealthCheck(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockRedisConnectionManager) Close() error {
	args := m.Called()
	return args.Error(0)
}
