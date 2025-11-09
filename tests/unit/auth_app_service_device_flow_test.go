// Package unit_test provides unit tests for the application services.
package unit_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service/mocks"
	"github.com/turtacn/cbc/pkg/errors"
)

type DeviceAuthAppServiceTestSuite struct {
	t *testing.T
	mockDeviceAuthStore *mocks.DeviceAuthStore
	mockTokenService    *mocks.TokenService
	mockKMS             *mocks.KeyManagementService
	cfg                 *config.OAuthConfig
	sut                 service.DeviceAuthAppService
}

func (s *DeviceAuthAppServiceTestSuite) SetupTest() {
	s.mockDeviceAuthStore = new(mocks.DeviceAuthStore)
	s.mockTokenService = new(mocks.TokenService)
	s.mockKMS = new(mocks.KeyManagementService)
	s.cfg = &config.OAuthConfig{
		DeviceAuthExpiresIn: 600 * time.Second,
		DeviceAuthInterval:  5 * time.Second,
		VerificationURI:     "https://example.com/verify",
	}
	s.sut = service.NewDeviceAuthAppService(s.mockDeviceAuthStore, s.mockTokenService, s.mockKMS, s.cfg)
}

func TestDeviceAuthAppService(t *testing.T) {
	// This function acts as a runner for all the sub-tests in the suite.
	// It ensures that each test case is run independently.
	suite := &DeviceAuthAppServiceTestSuite{}

	t.Run("PollDeviceToken_HappyPath", func(t *testing.T) {
		suite.t = t
		suite.SetupTest()
		suite.testPollDeviceTokenHappyPath(t)
	})
	t.Run("PollDeviceToken_Pending", func(t *testing.T) {
		suite.t = t
		suite.SetupTest()
		suite.testPollDeviceTokenPending(t)
	})
	t.Run("PollDeviceToken_SlowDown", func(t *testing.T) {
		suite.t = t
		suite.SetupTest()
		suite.testPollDeviceTokenSlowDown(t)
	})
	t.Run("PollDeviceToken_Denied", func(t *testing.T) {
		suite.t = t
		suite.SetupTest()
		suite.testPollDeviceTokenDenied(t)
	})
	t.Run("PollDeviceToken_Expired", func(t *testing.T) {
		suite.t = t
		suite.SetupTest()
		suite.testPollDeviceTokenExpired(t)
	})
}

func (s *DeviceAuthAppServiceTestSuite) testPollDeviceTokenHappyPath(t *testing.T) {
	// Arrange
	ctx := context.Background()
	deviceCode := "test-device-code"
	clientID := "test-client-id"
	userCode := "test-user-code"
	tenantID := "test-tenant-id"
	subject := "test-subject"
	scope := "test-scope"
	accessTokenString := "test-access-token"
	refreshTokenString := "test-refresh-token"

	approvedSession := &models.DeviceAuthSession{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		Status:     models.DeviceAuthStatusApproved,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		LastPollAt: time.Now().Add(-10 * time.Second), // Polled 10 seconds ago
		TenantID:   tenantID,
		Subject:    subject,
	}

	refreshToken := &models.Token{JTI: "refresh-jti"}
	accessToken := &models.Token{JTI: "access-jti", ExpiresAt: time.Now().Add(15 * time.Minute)}

	s.mockDeviceAuthStore.On("GetSessionByDeviceCode", ctx, deviceCode).Return(approvedSession, nil)
	s.mockDeviceAuthStore.On("TouchPoll", ctx, deviceCode).Return(nil)
	s.mockTokenService.On("IssueTokenPair", ctx, tenantID, subject, "", []string{scope}, mock.Anything).Return(refreshToken, accessToken, nil)
	s.mockKMS.On("GenerateJWT", ctx, tenantID, mock.AnythingOfType("*models.Claims")).Return(accessTokenString, "kid", nil).Once()
	s.mockKMS.On("GenerateJWT", ctx, tenantID, mock.AnythingOfType("*models.Claims")).Return(refreshTokenString, "kid", nil).Once()
	s.mockDeviceAuthStore.On("DenySession", ctx, userCode).Return(nil)

	// Act
	tokenResponse, err := s.sut.PollDeviceToken(ctx, deviceCode, clientID)

	// Assert
	assert.NoError(s.t, err)
	assert.NotNil(s.t, tokenResponse)
	assert.Equal(s.t, accessTokenString, tokenResponse.AccessToken)
	assert.Equal(s.t, refreshTokenString, tokenResponse.RefreshToken)
	s.mockDeviceAuthStore.AssertCalled(s.t, "DenySession", ctx, userCode)
}

func (s *DeviceAuthAppServiceTestSuite) testPollDeviceTokenPending(t *testing.T) {
	// Arrange
	ctx := context.Background()
	deviceCode := "test-device-code"
	clientID := "test-client-id"

	pendingSession := &models.DeviceAuthSession{
		DeviceCode: deviceCode,
		ClientID:   clientID,
		Status:     models.DeviceAuthStatusPending,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		LastPollAt: time.Now().Add(-10 * time.Second),
	}

	s.mockDeviceAuthStore.On("GetSessionByDeviceCode", ctx, deviceCode).Return(pendingSession, nil)
	s.mockDeviceAuthStore.On("TouchPoll", ctx, deviceCode).Return(nil)

	// Act
	_, err := s.sut.PollDeviceToken(ctx, deviceCode, clientID)

	// Assert
	assert.Error(s.t, err)
	cbcErr, ok := errors.AsCBCError(err)
	assert.True(s.t, ok)
	assert.Equal(s.t, errors.ErrCodeAuthorizationPending, string(cbcErr.Code()))
}

func (s *DeviceAuthAppServiceTestSuite) testPollDeviceTokenSlowDown(t *testing.T) {
	// Arrange
	ctx := context.Background()
	deviceCode := "test-device-code"
	clientID := "test-client-id"

	session := &models.DeviceAuthSession{
		DeviceCode: deviceCode,
		ClientID:   clientID,
		Status:     models.DeviceAuthStatusPending,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		LastPollAt: time.Now().Add(-1 * time.Second), // Polled 1 second ago
	}

	s.mockDeviceAuthStore.On("GetSessionByDeviceCode", ctx, deviceCode).Return(session, nil)

	// Act
	_, err := s.sut.PollDeviceToken(ctx, deviceCode, clientID)

	// Assert
	assert.Error(s.t, err)
	cbcErr, ok := errors.AsCBCError(err)
	assert.True(s.t, ok)
	assert.Equal(s.t, errors.ErrCodeSlowDown, string(cbcErr.Code()))
	s.mockDeviceAuthStore.AssertNotCalled(s.t, "TouchPoll", ctx, deviceCode)
}

func (s *DeviceAuthAppServiceTestSuite) testPollDeviceTokenDenied(t *testing.T) {
	// Arrange
	ctx := context.Background()
	deviceCode := "test-device-code"
	clientID := "test-client-id"

	deniedSession := &models.DeviceAuthSession{
		DeviceCode: deviceCode,
		ClientID:   clientID,
		Status:     models.DeviceAuthStatusDenied,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		LastPollAt: time.Now().Add(-10 * time.Second),
	}

	s.mockDeviceAuthStore.On("GetSessionByDeviceCode", ctx, deviceCode).Return(deniedSession, nil)
	s.mockDeviceAuthStore.On("TouchPoll", ctx, deviceCode).Return(nil)

	// Act
	_, err := s.sut.PollDeviceToken(ctx, deviceCode, clientID)

	// Assert
	assert.Error(s.t, err)
	cbcErr, ok := errors.AsCBCError(err)
	assert.True(s.t, ok)
	assert.Equal(s.t, errors.ErrCodeAccessDenied, string(cbcErr.Code()))
}

func (s *DeviceAuthAppServiceTestSuite) testPollDeviceTokenExpired(t *testing.T) {
	// Arrange
	ctx := context.Background()
	deviceCode := "test-device-code"
	clientID := "test-client-id"

	expiredSession := &models.DeviceAuthSession{
		DeviceCode: deviceCode,
		ClientID:   clientID,
		Status:     models.DeviceAuthStatusPending,
		ExpiresAt:  time.Now().Add(-1 * time.Second), // Expired 1 second ago
	}

	s.mockDeviceAuthStore.On("GetSessionByDeviceCode", ctx, deviceCode).Return(expiredSession, nil)

	// Act
	_, err := s.sut.PollDeviceToken(ctx, deviceCode, clientID)

	// Assert
	assert.Error(s.t, err)
	cbcErr, ok := errors.AsCBCError(err)
	assert.True(s.t, ok)
	assert.Equal(s.t, errors.ErrCodeExpiredToken, string(cbcErr.Code()))
}
