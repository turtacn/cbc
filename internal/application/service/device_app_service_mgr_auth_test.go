package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service/mocks"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type mockDeviceRepository struct {
	mock.Mock
}

func (m *mockDeviceRepository) FindByID(ctx context.Context, id string) (*models.Device, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Device), args.Error(1)
}

func (m *mockDeviceRepository) Save(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

func (m *mockDeviceRepository) FindByTenantID(ctx context.Context, tenantID string, page, pageSize int) ([]*models.Device, int64, error) {
	args := m.Called(ctx, tenantID, page, pageSize)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*models.Device), int64(args.Int(1)), args.Error(2)
}

func (m *mockDeviceRepository) Update(ctx context.Context, device *models.Device) error {
	args := m.Called(ctx, device)
	return args.Error(0)
}

type mockMgrKeyFetcher struct {
	mock.Mock
}

func (m *mockMgrKeyFetcher) GetMgrPublicKey(ctx context.Context, clientID, kid string) (*rsa.PublicKey, error) {
	args := m.Called(ctx, clientID, kid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

type mockPolicyService struct {
	mock.Mock
}

func (m *mockPolicyService) EvaluateTrustLevel(ctx context.Context, fingerprint string) (string, error) {
	args := m.Called(ctx, fingerprint)
	return args.String(0), args.Error(1)
}

func (m *mockPolicyService) EvaluateContextAccess(ctx context.Context, claims jwt.MapClaims, e_context map[string]interface{}) (bool, error) {
	args := m.Called(ctx, claims, e_context)
	return args.Bool(0), args.Error(1)
}

func TestDeviceAppService_RegisterDevice_MgrAuth(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	clientID := "test-client"
	kid := "test-kid"

	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"aud": "http://localhost:8080",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	validAssertion, err := token.SignedString(privKey)
	assert.NoError(t, err)

	// Create a token with a different key
	otherPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	invalidToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	invalidToken.Header["kid"] = kid
	invalidAssertion, err := invalidToken.SignedString(otherPrivKey)
	assert.NoError(t, err)

	testCases := []struct {
		name          string
		assertion     string
		setupMocks    func(*mockMgrKeyFetcher, *mockDeviceRepository, *mockPolicyService)
		expectedError bool
	}{
		{
			name:      "Valid assertion",
			assertion: validAssertion,
			setupMocks: func(keyFetcher *mockMgrKeyFetcher, deviceRepo *mockDeviceRepository, policyService *mockPolicyService) {
				keyFetcher.On("GetMgrPublicKey", mock.Anything, clientID, kid).Return(&privKey.PublicKey, nil)
				deviceRepo.On("FindByID", mock.Anything, mock.Anything).Return(nil, errors.New(errors.ErrCodeNotFound, "", ""))
				policyService.On("EvaluateTrustLevel", mock.Anything, mock.Anything).Return("medium", nil)
				deviceRepo.On("Save", mock.Anything, mock.Anything).Return(nil)
			},
			expectedError: false,
		},
		{
			name:      "Invalid signature",
			assertion: invalidAssertion,
			setupMocks: func(keyFetcher *mockMgrKeyFetcher, deviceRepo *mockDeviceRepository, policyService *mockPolicyService) {
				keyFetcher.On("GetMgrPublicKey", mock.Anything, clientID, kid).Return(&privKey.PublicKey, nil)
			},
			expectedError: true,
		},
		{
			name: "Invalid issuer",
			assertion: func() string {
				claims := jwt.MapClaims{
					"iss": "invalid-issuer",
					"sub": clientID,
					"exp": time.Now().Add(1 * time.Hour).Unix(),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				token.Header["kid"] = kid
				assertion, _ := token.SignedString(privKey)
				return assertion
			}(),
			setupMocks: func(keyFetcher *mockMgrKeyFetcher, deviceRepo *mockDeviceRepository, policyService *mockPolicyService) {
				keyFetcher.On("GetMgrPublicKey", mock.Anything, clientID, kid).Return(&privKey.PublicKey, nil)
			},
			expectedError: true,
		},
		{
			name: "Expired token",
			assertion: func() string {
				claims := jwt.MapClaims{
					"iss": clientID,
					"sub": clientID,
					"exp": time.Now().Add(-1 * time.Hour).Unix(),
					"aud": "http://localhost:8080",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				token.Header["kid"] = kid
				assertion, _ := token.SignedString(privKey)
				return assertion
			}(),
			setupMocks: func(keyFetcher *mockMgrKeyFetcher, deviceRepo *mockDeviceRepository, policyService *mockPolicyService) {
				keyFetcher.On("GetMgrPublicKey", mock.Anything, clientID, kid).Return(&privKey.PublicKey, nil)
			},
			expectedError: true,
		},
		{
			name: "Invalid audience",
			assertion: func() string {
				claims := jwt.MapClaims{
					"iss": clientID,
					"sub": clientID,
					"exp": time.Now().Add(1 * time.Hour).Unix(),
					"aud": "invalid-audience",
				}
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				token.Header["kid"] = kid
				assertion, _ := token.SignedString(privKey)
				return assertion
			}(),
			setupMocks: func(keyFetcher *mockMgrKeyFetcher, deviceRepo *mockDeviceRepository, policyService *mockPolicyService) {
				keyFetcher.On("GetMgrPublicKey", mock.Anything, clientID, kid).Return(&privKey.PublicKey, nil)
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyFetcher := new(mockMgrKeyFetcher)
			deviceRepo := new(mockDeviceRepository)
			policyService := new(mockPolicyService)
			auditService := new(mocks.MockAuditService)
			auditService.On("LogEvent", mock.Anything, mock.Anything).Return(nil)
			tokenService := new(mocks.MockTokenService)
			tokenService.On("IssueTokenPair", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(&models.Token{JTI: "test"}, &models.Token{}, nil)
			cfg := &config.Config{Server: config.ServerConfig{IssuerURL: "http://localhost:8080"}}

			service := NewDeviceAppService(deviceRepo, auditService, keyFetcher, policyService, tokenService, cfg, logger.NewDefaultLogger())

			tc.setupMocks(keyFetcher, deviceRepo, policyService)

			req := &dto.RegisterDeviceRequest{
				ClientID:        clientID,
				ClientAssertion: tc.assertion,
				AgentID:         "test-agent",
			}
			_, err := service.RegisterDevice(context.Background(), req)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
