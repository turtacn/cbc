// internal/domain/service/token_domain_service_test.go
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

// MockTokenRepository 是 TokenRepository 的模拟实现
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) Create(ctx context.Context, token *models.Token) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockTokenRepository) FindByJTI(ctx context.Context, jti string) (*models.Token, error) {
	args := m.Called(ctx, jti)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenRepository) RevokeByJTI(ctx context.Context, jti, reason string) error {
	args := m.Called(ctx, jti, reason)
	return args.Error(0)
}

func (m *MockTokenRepository) RevokeByDevice(ctx context.Context, tenantID, deviceID uuid.UUID, reason string) error {
	args := m.Called(ctx, tenantID, deviceID, reason)
	return args.Error(0)
}

func (m *MockTokenRepository) CleanExpiredTokens(ctx context.Context, before time.Time) (int64, error) {
	args := m.Called(ctx, before)
	return args.Get(0).(int64), args.Error(1)
}

func TestTokenDomainService_CreateToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	service := NewTokenDomainService(mockRepo)
	ctx := context.Background()

	tenantID := uuid.New()
	deviceID := uuid.New()
	jti := uuid.New().String()
	tokenType := models.TokenTypeAccess
	scope := "agent:read agent:write"
	ttl := 15 * time.Minute

	tests := []struct {
		name      string
		setupMock func()
		wantErr   bool
	}{
		{
			name: "Successfully create token",
			setupMock: func() {
				mockRepo.On("Create", ctx, mock.MatchedBy(func(token *models.Token) bool {
					return token.JTI == jti &&
						token.TenantID == tenantID &&
						token.DeviceID == deviceID &&
						token.TokenType == tokenType &&
						token.Scope == scope
				})).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Repository error",
			setupMock: func() {
				mockRepo.On("Create", ctx, mock.Anything).
					Return(errors.ErrDatabaseError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			token, err := service.CreateToken(ctx, tenantID, deviceID, jti, tokenType, scope, ttl)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, jti, token.JTI)
				assert.Equal(t, tenantID, token.TenantID)
				assert.Equal(t, deviceID, token.DeviceID)
				assert.Equal(t, tokenType, token.TokenType)
				assert.Equal(t, scope, token.Scope)
				assert.False(t, token.IssuedAt.IsZero())
				assert.False(t, token.ExpiresAt.IsZero())
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestTokenDomainService_ValidateToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	service := NewTokenDomainService(mockRepo)
	ctx := context.Background()

	jti := uuid.New().String()
	now := time.Now()

	tests := []struct {
		name      string
		jti       string
		setupMock func()
		wantErr   bool
		errType   error
	}{
		{
			name: "Valid active token",
			jti:  jti,
			setupMock: func() {
				validToken := &models.Token{
					ID:        uuid.New(),
					JTI:       jti,
					TenantID:  uuid.New(),
					DeviceID:  uuid.New(),
					TokenType: models.TokenTypeAccess,
					Scope:     "agent:read",
					IssuedAt:  now.Add(-1 * time.Minute),
					ExpiresAt: now.Add(15 * time.Minute),
					RevokedAt: nil,
					CreatedAt: now,
				}
				mockRepo.On("FindByJTI", ctx, jti).Return(validToken, nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Token not found",
			jti:  "non-existent-jti",
			setupMock: func() {
				mockRepo.On("FindByJTI", ctx, "non-existent-jti").
					Return(nil, errors.ErrTokenNotFound).Once()
			},
			wantErr: true,
			errType: errors.ErrTokenNotFound,
		},
		{
			name: "Expired token",
			jti:  jti,
			setupMock: func() {
				expiredToken := &models.Token{
					ID:        uuid.New(),
					JTI:       jti,
					TenantID:  uuid.New(),
					DeviceID:  uuid.New(),
					TokenType: models.TokenTypeAccess,
					Scope:     "agent:read",
					IssuedAt:  now.Add(-2 * time.Hour),
					ExpiresAt: now.Add(-1 * time.Hour),
					RevokedAt: nil,
					CreatedAt: now.Add(-2 * time.Hour),
				}
				mockRepo.On("FindByJTI", ctx, jti).Return(expiredToken, nil).Once()
			},
			wantErr: true,
			errType: errors.ErrTokenExpired,
		},
		{
			name: "Revoked token",
			jti:  jti,
			setupMock: func() {
				revokedToken := &models.Token{
					ID:        uuid.New(),
					JTI:       jti,
					TenantID:  uuid.New(),
					DeviceID:  uuid.New(),
					TokenType: models.TokenTypeAccess,
					Scope:     "agent:read",
					IssuedAt:  now.Add(-1 * time.Minute),
					ExpiresAt: now.Add(15 * time.Minute),
					RevokedAt: &now,
					CreatedAt: now,
				}
				mockRepo.On("FindByJTI", ctx, jti).Return(revokedToken, nil).Once()
			},
			wantErr: true,
			errType: errors.ErrTokenRevoked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			token, err := service.ValidateToken(ctx, tt.jti)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, token)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
				assert.Equal(t, tt.jti, token.JTI)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestTokenDomainService_RevokeToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	service := NewTokenDomainService(mockRepo)
	ctx := context.Background()

	jti := uuid.New().String()
	reason := "user_logout"

	tests := []struct {
		name      string
		setupMock func()
		wantErr   bool
	}{
		{
			name: "Successfully revoke token",
			setupMock: func() {
				mockRepo.On("RevokeByJTI", ctx, jti, reason).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Token not found",
			setupMock: func() {
				mockRepo.On("RevokeByJTI", ctx, jti, reason).
					Return(errors.ErrTokenNotFound).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := service.RevokeToken(ctx, jti, reason)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestTokenDomainService_RevokeDeviceTokens(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	service := NewTokenDomainService(mockRepo)
	ctx := context.Background()

	tenantID := uuid.New()
	deviceID := uuid.New()
	reason := "device_compromised"

	tests := []struct {
		name      string
		setupMock func()
		wantErr   bool
	}{
		{
			name: "Successfully revoke device tokens",
			setupMock: func() {
				mockRepo.On("RevokeByDevice", ctx, tenantID, deviceID, reason).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Repository error",
			setupMock: func() {
				mockRepo.On("RevokeByDevice", ctx, tenantID, deviceID, reason).
					Return(errors.ErrDatabaseError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := service.RevokeDeviceTokens(ctx, tenantID, deviceID, reason)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestTokenDomainService_CleanupExpiredTokens(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	service := NewTokenDomainService(mockRepo)
	ctx := context.Background()

	tests := []struct {
		name      string
		setupMock func()
		wantCount int64
		wantErr   bool
	}{
		{
			name: "Successfully cleanup expired tokens",
			setupMock: func() {
				mockRepo.On("CleanExpiredTokens", ctx, mock.AnythingOfType("time.Time")).
					Return(int64(150), nil).Once()
			},
			wantCount: 150,
			wantErr:   false,
		},
		{
			name: "No expired tokens to clean",
			setupMock: func() {
				mockRepo.On("CleanExpiredTokens", ctx, mock.AnythingOfType("time.Time")).
					Return(int64(0), nil).Once()
			},
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "Repository error",
			setupMock: func() {
				mockRepo.On("CleanExpiredTokens", ctx, mock.AnythingOfType("time.Time")).
					Return(int64(0), errors.ErrDatabaseError).Once()
			},
			wantCount: 0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			count, err := service.CleanupExpiredTokens(ctx)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, count)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

//Personal.AI order the ending
