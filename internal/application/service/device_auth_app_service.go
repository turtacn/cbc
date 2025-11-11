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

//go:generate mockery --name DeviceAuthAppService --output ./mocks --filename mock_device_auth_app_service.go --structname MockDeviceAuthAppService
// DeviceAuthAppService defines the interface for the OAuth 2.0 Device Authorization Grant flow.
// It handles the three main parts of the flow: starting the flow, user verification, and token polling.
// DeviceAuthAppService 定义了 OAuth 2.0 设备授权授予流程的接口。
// 它处理流程的三个主要部分：启动流程、用户验证和令牌轮询。
type DeviceAuthAppService interface {
	// StartDeviceFlow initiates the device authorization flow by generating a device_code and user_code.
	// StartDeviceFlow 通过生成 device_code 和 user_code 来启动设备授权流程。
	StartDeviceFlow(ctx context.Context, clientID, scope string) (*dto.DeviceAuthResponse, error)
	// VerifyDeviceFlow is called by the end-user on a secondary device to approve or deny the request.
	// VerifyDeviceFlow 由最终用户在辅助设备上调用，以批准或拒绝请求。
	VerifyDeviceFlow(ctx context.Context, userCode, action, tenantID, subject string) error
	// PollDeviceToken is called by the device to poll for the token after the user has completed verification.
	// PollDeviceToken 在用户完成验证后由设备调用以轮询令牌。
	PollDeviceToken(ctx context.Context, deviceCode, clientID string) (*dto.TokenResponse, error)
}

// deviceAuthAppServiceImpl is the concrete implementation of the DeviceAuthAppService interface.
// deviceAuthAppServiceImpl 是 DeviceAuthAppService 接口的具体实现。
type deviceAuthAppServiceImpl struct {
	deviceAuthStore service.DeviceAuthStore
	tokenService    service.TokenService
	kms             service.KeyManagementService
	cfg             *config.OAuthConfig
}

// NewDeviceAuthAppService creates a new instance of DeviceAuthAppService.
// NewDeviceAuthAppService 创建一个新的 DeviceAuthAppService 实例。
func NewDeviceAuthAppService(
	deviceAuthStore service.DeviceAuthStore,
	tokenService service.TokenService,
	kms service.KeyManagementService,
	cfg *config.OAuthConfig,
) DeviceAuthAppService {
	return &deviceAuthAppServiceImpl{
		deviceAuthStore: deviceAuthStore,
		tokenService:    tokenService,
		kms:             kms,
		cfg:             cfg,
	}
}

// StartDeviceFlow begins the device authorization flow. It generates unique codes, creates a session, and returns the necessary information to the device.
// StartDeviceFlow 开始设备授权流程。它生成唯一的代码，创建一个会话，并将必要的信息返回给设备。
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

// VerifyDeviceFlow allows the end-user to approve or deny the authorization request associated with a user code.
// VerifyDeviceFlow 允许最终用户批准或拒绝与用户代码关联的授权请求。
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

// PollDeviceToken is polled by the device to check the status of the authorization and retrieve the tokens upon approval.
// It handles different states like pending, approved, denied, expired, and enforces polling intervals.
// PollDeviceToken 由设备轮询以检查授权状态并在批准后检索令牌。
// 它处理不同的状态，如待定、已批准、已拒绝、已过期，并强制执行轮询间隔。
func (s *deviceAuthAppServiceImpl) PollDeviceToken(ctx context.Context, deviceCode, clientID string) (*dto.TokenResponse, error) {
	session, err := s.deviceAuthStore.GetSessionByDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, errors.ErrDeviceFlowExpiredToken()
	}

	if session.ClientID != clientID {
		return nil, errors.ErrInvalidClient("client_id does not match")
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, errors.ErrDeviceFlowExpiredToken()
	}

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

		accessTokenString, _, err := s.kms.GenerateJWT(ctx, session.TenantID, accessToken.ToClaims())
		if err != nil {
			return nil, errors.ErrServerError("failed to generate access token string").WithCause(err)
		}
		refreshTokenString, _, err := s.kms.GenerateJWT(ctx, session.TenantID, refreshToken.ToClaims())
		if err != nil {
			return nil, errors.ErrServerError("failed to generate refresh token string").WithCause(err)
		}

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
