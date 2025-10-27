// internal/interfaces/grpc/auth_grpc_service_test.go
package grpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	authpb "github.com/turtacn/cbc/internal/interfaces/grpc/proto"
	"github.com/turtacn/cbc/pkg/logger"
)

// MockAuthAppService is a mock for the AuthAppService
type MockAuthAppService struct {
	mock.Mock
}

func (m *MockAuthAppService) IssueToken(ctx context.Context, req *dto.IssueTokenRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

func (m *MockAuthAppService) RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

func (m *MockAuthAppService) RevokeToken(ctx context.Context, req *dto.RevokeTokenRequest) error {
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

func TestAuthGRPCService_IssueToken(t *testing.T) {
	mockAppService := new(MockAuthAppService)
	log := logger.NewDefaultLogger()
	grpcService := NewAuthGRPCService(mockAppService, log)

	ctx := context.Background()
	tenantID := uuid.New().String()
	deviceID := uuid.New().String()

	tests := []struct {
		name          string
		grpcRequest   *authpb.IssueTokenRequest
		mockResponse  *dto.TokenResponse
		mockError     error
		expectedScope []string
		wantErr       bool
	}{
		{
			name: "Successfully issue token",
			grpcRequest: &authpb.IssueTokenRequest{
				TenantId:  tenantID,
				DeviceId:  deviceID,
				GrantType: "client_credentials",
				Scope:     []string{"agent:read", "agent:write"},
				Credentials: &authpb.ClientCredentials{
					ClientId:     "mgr-client",
					ClientAssertion: "some-jwt",
				},
				DeviceInfo: &authpb.DeviceInfo{
					DeviceFingerprint: "fingerprint-hash",
					OsType:           "Linux",
				},
			},
			mockResponse: &dto.TokenResponse{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				Scope:        "agent:read agent:write",
			},
			mockError:     nil,
			expectedScope: []string{"agent:read", "agent:write"},
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAppService.On("IssueToken", ctx, mock.MatchedBy(func(req *dto.IssueTokenRequest) bool {
				return req.TenantID == tt.grpcRequest.TenantId && req.GrantType == tt.grpcRequest.GrantType
			})).Return(tt.mockResponse, tt.mockError).Once()

			resp, err := grpcService.IssueToken(ctx, tt.grpcRequest)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.mockResponse.AccessToken, resp.AccessToken)
				assert.Equal(t, tt.expectedScope, resp.Scope)
			}

			mockAppService.AssertExpectations(t)
		})
	}
}
