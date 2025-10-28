// internal/domain/service/token_domain_service_test.go
package service

import (
	"context"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
	customErr "github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/constants"
)

// MockTokenRepository is a mock for the TokenRepository
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

// MockCryptoService is a mock for the CryptoService
type MockCryptoService struct {
	mock.Mock
}

func (m *MockCryptoService) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
	args := m.Called(ctx, tenantID, claims)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockCryptoService) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	args := m.Called(ctx, tokenString, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(jwt.MapClaims), args.Error(1)
}

func (m *MockCryptoService) ParseJWT(tokenString string) (*jwt.Token, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.Token), args.Error(1)
}

func (m *MockCryptoService) GetPublicKey(ctx context.Context, tenantID string, keyID string) (*rsa.PublicKey, error) {
	args := m.Called(ctx, tenantID, keyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

func (m *MockCryptoService) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).(*rsa.PrivateKey), args.String(1), args.Error(2)
}

func (m *MockCryptoService) GetPublicKeyJWKS(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

func (m *MockCryptoService) RotateKey(ctx context.Context, tenantID string) (string, error) {
	args := m.Called(ctx, tenantID)
	return args.String(0), args.Error(1)
}

func (m *MockCryptoService) RevokeKey(ctx context.Context, tenantID string, keyID string, reason string) error {
	args := m.Called(ctx, tenantID, keyID, reason)
	return args.Error(0)
}

func (m *MockCryptoService) ValidateJWTHeader(header map[string]interface{}) (bool, error) {
	args := m.Called(header)
	return args.Bool(0), args.Error(1)
}

func (m *MockCryptoService) ValidateStandardClaims(claims jwt.MapClaims, clockSkew int64) (bool, error) {
	args := m.Called(claims, clockSkew)
	return args.Bool(0), args.Error(1)
}

func (m *MockCryptoService) ExtractKeyID(tokenString string) (string, error) {
	args := m.Called(tokenString)
	return args.String(0), args.Error(1)
}

func (m *MockCryptoService) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	args := m.Called(ctx, data)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockCryptoService) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	args := m.Called(ctx, data)
	return args.Get(0).([]byte), args.Error(1)
}

func TestTokenDomainService_RefreshToken(t *testing.T) {
	mockRepo := new(MockTokenRepository)
	mockCrypto := new(MockCryptoService)
	service := NewTokenDomainService(mockRepo, mockCrypto, logger.NewDefaultLogger())

	ctx := context.Background()
	refreshTokenString := "valid-refresh-token"
	tenantID := uuid.New().String()
	jti := uuid.New().String()
	now := time.Now()

	claims := jwt.MapClaims{
		"jti":       jti,
		"tenant_id": tenantID,
		"token_type": string(constants.TokenTypeRefresh),
		"exp":       float64(now.Add(1 * time.Hour).Unix()),
	}
	token := &models.Token{
		JTI:      jti,
		TenantID: tenantID,
	}

	tests := []struct {
		name          string
		setupMocks    func()
		wantErr       bool
		expectedError error
	}{
		{
			name: "Successfully refresh token",
			setupMocks: func() {
				mockCrypto.On("VerifyJWT", ctx, refreshTokenString, "").Return(claims, nil).Once()
				mockRepo.On("FindByJTI", ctx, jti).Return(token, nil).Once()
				mockRepo.On("IsRevoked", ctx, jti).Return(false, nil).Once()
				mockRepo.On("Revoke", ctx, jti, "rotated").Return(nil).Once()
				mockRepo.On("Save", ctx, mock.AnythingOfType("*models.Token")).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name: "Refresh token is expired",
			setupMocks: func() {
				expiredClaims := jwt.MapClaims{"exp": float64(now.Add(-1 * time.Minute).Unix())}
				mockCrypto.On("VerifyJWT", ctx, refreshTokenString, "").Return(expiredClaims, errors.New("token is expired")).Once()
			},
			wantErr:       true,
			expectedError: customErr.ErrTokenExpired(string(constants.TokenTypeRefresh)),
		},
		{
			name: "Refresh token has been revoked",
			setupMocks: func() {
				mockCrypto.On("VerifyJWT", ctx, refreshTokenString, "").Return(claims, nil).Once()
				mockRepo.On("FindByJTI", ctx, jti).Return(token, nil).Once()
				mockRepo.On("IsRevoked", ctx, jti).Return(true, nil).Once()
			},
			wantErr:       true,
			expectedError: customErr.ErrTokenRevoked(string(constants.TokenTypeRefresh), jti),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks before each run
			mockRepo.Mock = mock.Mock{}
			mockCrypto.Mock = mock.Mock{}
			tt.setupMocks()

			_, _, err := service.RefreshToken(ctx, refreshTokenString, nil)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockRepo.AssertExpectations(t)
			mockCrypto.AssertExpectations(t)
		})
	}
}
