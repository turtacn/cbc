// internal/interfaces/grpc/auth_grpc_service_test.go
package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	pb "github.com/turtacn/cbc/internal/interfaces/grpc/proto"
	"github.com/turtacn/cbc/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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

func (m *MockAuthAppService) ValidateToken(ctx context.Context, req *dto.ValidateTokenRequest) (*dto.TokenValidationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenValidationResponse), args.Error(1)
}

func TestAuthGRPCService_IssueToken(t *testing.T) {
	mockService := new(MockAuthAppService)
	grpcService := NewAuthGRPCService(mockService)

	tenantID := uuid.New()
	deviceID := uuid.New()

	tests := []struct {
		name      string
		request   *pb.IssueTokenRequest
		setupMock func()
		wantErr   bool
		wantCode  codes.Code
	}{
		{
			name: "Successfully issue token",
			request: &pb.IssueTokenRequest{
				TenantId:    tenantID.String(),
				DeviceId:    deviceID.String(),
				DeviceType:  "mobile",
				Fingerprint: "test-fingerprint",
				Scope:       "agent:read agent:write",
			},
			setupMock: func() {
				response := &dto.TokenResponse{
					AccessToken:  "jwt.access.token",
					RefreshToken: "jwt.refresh.token",
					TokenType:    "Bearer",
					ExpiresIn:    900,
				}
				mockService.On("IssueToken", mock.Anything, mock.Anything).
					Return(response, nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Invalid tenant ID",
			request: &pb.IssueTokenRequest{
				TenantId:    "invalid-uuid",
				DeviceId:    deviceID.String(),
				DeviceType:  "mobile",
				Fingerprint: "test-fingerprint",
				Scope:       "agent:read",
			},
			setupMock: func() {},
			wantErr:   true,
			wantCode:  codes.InvalidArgument,
		},
		{
			name: "Tenant not found",
			request: &pb.IssueTokenRequest{
				TenantId:    tenantID.String(),
				DeviceId:    deviceID.String(),
				DeviceType:  "mobile",
				Fingerprint: "test-fingerprint",
				Scope:       "agent:read",
			},
			setupMock: func() {
				mockService.On("IssueToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrTenantNotFound).Once()
			},
			wantErr:  true,
			wantCode: codes.NotFound,
		},
		{
			name: "Rate limit exceeded",
			request: &pb.IssueTokenRequest{
				TenantId:    tenantID.String(),
				DeviceId:    deviceID.String(),
				DeviceType:  "mobile",
				Fingerprint: "test-fingerprint",
				Scope:       "agent:read",
			},
			setupMock: func() {
				mockService.On("IssueToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrRateLimitExceeded).Once()
			},
			wantErr:  true,
			wantCode: codes.ResourceExhausted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := grpcService.IssueToken(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, "jwt.access.token", resp.AccessToken)
				assert.Equal(t, "jwt.refresh.token", resp.RefreshToken)
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.Equal(t, int64(900), resp.ExpiresIn)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthGRPCService_RefreshToken(t *testing.T) {
	mockService := new(MockAuthAppService)
	grpcService := NewAuthGRPCService(mockService)

	tests := []struct {
		name      string
		request   *pb.RefreshTokenRequest
		setupMock func()
		wantErr   bool
		wantCode  codes.Code
	}{
		{
			name: "Successfully refresh token",
			request: &pb.RefreshTokenRequest{
				RefreshToken: "valid.refresh.token",
			},
			setupMock: func() {
				response := &dto.TokenResponse{
					AccessToken:  "new.access.token",
					RefreshToken: "new.refresh.token",
					TokenType:    "Bearer",
					ExpiresIn:    900,
				}
				mockService.On("RefreshToken", mock.Anything, mock.Anything).
					Return(response, nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Invalid refresh token",
			request: &pb.RefreshTokenRequest{
				RefreshToken: "invalid.token",
			},
			setupMock: func() {
				mockService.On("RefreshToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrInvalidToken).Once()
			},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "Expired refresh token",
			request: &pb.RefreshTokenRequest{
				RefreshToken: "expired.token",
			},
			setupMock: func() {
				mockService.On("RefreshToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrTokenExpired).Once()
			},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := grpcService.RefreshToken(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.AccessToken)
				assert.NotEmpty(t, resp.RefreshToken)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthGRPCService_ValidateToken(t *testing.T) {
	mockService := new(MockAuthAppService)
	grpcService := NewAuthGRPCService(mockService)

	tenantID := uuid.New()
	deviceID := uuid.New()

	tests := []struct {
		name      string
		request   *pb.ValidateTokenRequest
		setupMock func()
		wantErr   bool
		wantCode  codes.Code
	}{
		{
			name: "Valid token",
			request: &pb.ValidateTokenRequest{
				Token: "valid.access.token",
			},
			setupMock: func() {
				response := &dto.TokenValidationResponse{
					Valid:     true,
					TenantID:  tenantID,
					DeviceID:  deviceID,
					TokenType: "access",
					Scope:     "agent:read agent:write",
					ExpiresAt: time.Now().Add(15 * time.Minute),
				}
				mockService.On("ValidateToken", mock.Anything, mock.Anything).
					Return(response, nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Invalid token",
			request: &pb.ValidateTokenRequest{
				Token: "invalid.token",
			},
			setupMock: func() {
				mockService.On("ValidateToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrInvalidToken).Once()
			},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
		{
			name: "Expired token",
			request: &pb.ValidateTokenRequest{
				Token: "expired.token",
			},
			setupMock: func() {
				mockService.On("ValidateToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrTokenExpired).Once()
			},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := grpcService.ValidateToken(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Valid)
				assert.Equal(t, tenantID.String(), resp.TenantId)
				assert.Equal(t, deviceID.String(), resp.DeviceId)
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthGRPCService_RevokeToken(t *testing.T) {
	mockService := new(MockAuthAppService)
	grpcService := NewAuthGRPCService(mockService)

	tests := []struct {
		name      string
		request   *pb.RevokeTokenRequest
		setupMock func()
		wantErr   bool
		wantCode  codes.Code
	}{
		{
			name: "Successfully revoke token",
			request: &pb.RevokeTokenRequest{
				Token: "valid.token",
			},
			setupMock: func() {
				mockService.On("RevokeToken", mock.Anything, mock.Anything).
					Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Invalid token to revoke",
			request: &pb.RevokeTokenRequest{
				Token: "invalid.token",
			},
			setupMock: func() {
				mockService.On("RevokeToken", mock.Anything, mock.Anything).
					Return(errors.ErrInvalidToken).Once()
			},
			wantErr:  true,
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := grpcService.RevokeToken(context.Background(), tt.request)

			if tt.wantErr {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				assert.True(t, ok)
				assert.Equal(t, tt.wantCode, st.Code())
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Success)
			}

			mockService.AssertExpectations(t)
		})
	}
}
