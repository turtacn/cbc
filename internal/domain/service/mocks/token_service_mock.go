package mocks

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
)

type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) IssueTokenPair(ctx context.Context, tenantID string, agentID string, deviceFingerprint string, scope []string, metadata map[string]interface{}) (refreshToken *models.Token, accessToken *models.Token, err error) {
	args := m.Called(ctx, tenantID, agentID, deviceFingerprint, scope, metadata)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), args.Error(2)
}

func (m *MockTokenService) IssueToken(ctx context.Context, tenantID, subject string, scope []string) (*models.Token, error) {
	args := m.Called(ctx, tenantID, subject, scope)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenService) RefreshToken(ctx context.Context, refreshTokenString string, requestedScope []string) (newRefreshToken *models.Token, accessToken *models.Token, err error) {
	args := m.Called(ctx, refreshTokenString, requestedScope)
	if args.Get(0) == nil {
		return nil, nil, args.Error(2)
	}
	return args.Get(0).(*models.Token), args.Get(1).(*models.Token), args.Error(2)
}

func (m *MockTokenService) VerifyToken(ctx context.Context, tokenString string, tokenType constants.TokenType, tenantID string) (*models.Token, error) {
	args := m.Called(ctx, tokenString, tokenType, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Token), args.Error(1)
}

func (m *MockTokenService) RevokeToken(ctx context.Context, jti string, tenantID string, reason string) error {
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

func (m *MockTokenService) IntrospectToken(ctx context.Context, tokenString string, tokenTypeHint string) (*models.TokenIntrospection, error) {
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
