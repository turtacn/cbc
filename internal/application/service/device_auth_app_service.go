// Package service provides application-level services and use cases.
package service

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/utils"
)

// DeviceAuthAppService defines the interface for the device authorization flow.
type DeviceAuthAppService interface {
	StartDeviceFlow(ctx context.Context, clientID, scope string) (*dto.DeviceAuthResponse, error)
	VerifyDeviceFlow(ctx context.Context, userCode, action, tenantID, subject string) error
	PollDeviceToken(ctx context.Context, deviceCode, clientID string) (*dto.TokenResponse, error)
}

type deviceAuthAppServiceImpl struct {
	deviceAuthStore service.DeviceAuthStore
	tokenService    service.TokenService
	cryptoService   service.CryptoService
	cfg             *config.OAuthConfig
}

func NewDeviceAuthAppService(
	deviceAuthStore service.DeviceAuthStore,
	tokenService service.TokenService,
	cryptoService service.CryptoService,
	cfg *config.OAuthConfig,
) DeviceAuthAppService {
	return &deviceAuthAppServiceImpl{
		deviceAuthStore: deviceAuthStore,
		tokenService:    tokenService,
		cryptoService:   cryptoService,
		cfg:             cfg,
	}
}

func (s *deviceAuthAppServiceImpl) StartDeviceFlow(ctx context.Context, clientID, scope string) (*dto.DeviceAuthResponse, error) {
	deviceCode, err := utils.GenerateSecureRandomString(32)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to generate device code")
	}

	userCode, err := utils.GenerateSecureRandomString(8)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to generate user code")
	}

	expiresIn := int(s.cfg.DeviceAuthExpiresIn.Seconds())
	session := &models.DeviceAuthSession{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		Status:     models.DeviceAuthStatusPending,
		ExpiresAt:  time.Now().Add(s.cfg.DeviceAuthExpiresIn),
		Interval:   int(s.cfg.DeviceAuthInterval.Seconds()),
	}

	if err := s.deviceAuthStore.CreateSession(ctx, session); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to create device auth session")
	}

	return &dto.DeviceAuthResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationURI: s.cfg.VerificationURI,
		ExpiresIn:       expiresIn,
		Interval:        session.Interval,
	}, nil
}

func (s *deviceAuthAppServiceImpl) VerifyDeviceFlow(ctx context.Context, userCode, action, tenantID, subject string) error {
	session, err := s.deviceAuthStore.GetSessionByUserCode(ctx, userCode)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeNotFound, "device auth session not found")
	}

	if session.Status != models.DeviceAuthStatusPending {
		return errors.ErrInvalidRequest("device auth session is not in a pending state")
	}

	switch action {
	case "approve":
		return s.deviceAuthStore.ApproveSession(ctx, userCode, tenantID, subject)
	case "deny":
		return s.deviceAuthStore.DenySession(ctx, userCode)
	default:
		return errors.ErrInvalidRequest("invalid action")
	}
}

func (s *deviceAuthAppServiceImpl) PollDeviceToken(ctx context.Context, deviceCode, clientID string) (*dto.TokenResponse, error) {
	session, err := s.deviceAuthStore.GetSessionByDeviceCode(ctx, deviceCode)
	if err != nil {
		// Note: The store should return a specific 'not found' error.
		// For now, we assume any error is a not-found for the purpose of the RFC.
		return nil, errors.ErrDeviceFlowExpiredToken()
	}

	if session.ClientID != clientID {
		return nil, errors.ErrInvalidClient("client_id does not match")
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, errors.ErrDeviceFlowExpiredToken()
	}

	// slow_down logic
	if time.Since(session.LastPollAt) < s.cfg.DeviceAuthInterval {
		return nil, errors.ErrSlowDown()
	}

	if err := s.deviceAuthStore.TouchPoll(ctx, deviceCode); err != nil {
		return nil, errors.ErrServerError("failed to update poll time").WithCause(err)
	}

	switch session.Status {
	case models.DeviceAuthStatusPending:
		return nil, errors.ErrAuthorizationPending()
	case models.DeviceAuthStatusDenied:
		return nil, errors.ErrDeviceFlowAccessDenied()
	case models.DeviceAuthStatusApproved:
		refreshToken, accessToken, err := s.tokenService.IssueTokenPair(ctx, session.TenantID, session.Subject, "", []string{session.Scope}, nil)
		if err != nil {
			return nil, errors.ErrServerError("failed to issue token pair").WithCause(err)
		}

		// Generate JWT strings
		accessTokenString, _, err := s.cryptoService.GenerateJWT(ctx, session.TenantID, accessToken.ToClaims())
		if err != nil {
			return nil, errors.ErrServerError("failed to generate access token string").WithCause(err)
		}
		refreshTokenString, _, err := s.cryptoService.GenerateJWT(ctx, session.TenantID, refreshToken.ToClaims())
		if err != nil {
			return nil, errors.ErrServerError("failed to generate refresh token string").WithCause(err)
		}

		// The device code should be consumed after use. Denying it is a simple way to achieve this.
		if err := s.deviceAuthStore.DenySession(ctx, session.UserCode); err != nil {
			// Log the error but don't fail the request as the token has been issued.
		}

		return &dto.TokenResponse{
			AccessToken:  accessTokenString,
			RefreshToken: refreshTokenString,
			ExpiresIn:    int64(accessToken.TimeUntilExpiry().Seconds()),
			TokenType:    "Bearer",
			Scope:        session.Scope,
			IssuedAt:     accessToken.IssuedAt.Unix(),
		}, nil
	default:
		return nil, errors.ErrServerError("unknown device auth session status")
	}
}
