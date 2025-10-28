// Package service provides application-level services that orchestrate domain services and repositories
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	domainService "github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// AuthAppService defines the interface for authentication application service
type AuthAppService interface {
	// IssueToken issues a new token pair (access token + refresh token) for a device
	IssueToken(ctx context.Context, req *dto.IssueTokenRequest) (*dto.TokenResponse, error)

	// RefreshToken refreshes an access token using a valid refresh token
	RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest) (*dto.TokenResponse, error)

	// RevokeToken revokes a token (refresh token or access token)
	RevokeToken(ctx context.Context, req *dto.RevokeTokenRequest) error

	// IntrospectToken validates and returns token information
	IntrospectToken(ctx context.Context, token string) (*dto.TokenIntrospectionResponse, error)

	// RegisterDevice registers a new device and issues initial refresh token
	RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.TokenResponse, error)
}

// authAppServiceImpl is the concrete implementation of AuthAppService
type authAppServiceImpl struct {
	tokenService      domainService.TokenService
	deviceRepo        repository.DeviceRepository
	tenantRepo        repository.TenantRepository
	rateLimitService  domainService.RateLimitService
	logger            logger.Logger
}

// NewAuthAppService creates a new instance of AuthAppService
func NewAuthAppService(
	tokenService domainService.TokenService,
	deviceRepo repository.DeviceRepository,
	tenantRepo repository.TenantRepository,
	rateLimitService domainService.RateLimitService,
	log logger.Logger,
) AuthAppService {
	return &authAppServiceImpl{
		tokenService:     tokenService,
		deviceRepo:       deviceRepo,
		tenantRepo:       tenantRepo,
		rateLimitService: rateLimitService,
		logger:           log,
	}
}

// RegisterDevice implements device registration and initial token issuance
func (s *authAppServiceImpl) RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.TokenResponse, error) {
	// 1. Validate request payload
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid register device request", err)
		return nil, errors.New(errors.ErrCodeInvalidRequest, "invalid register device request", err.Error())
	}

	// 2. Defensive check for nil dependencies
	if s.tenantRepo == nil || s.rateLimitService == nil || s.deviceRepo == nil || s.tokenService == nil {
		s.logger.Error(ctx, "Service dependencies are not initialized", nil)
		return nil, errors.New(errors.ErrCodeInternal, "service dependencies not initialized", "")
	}

	// 3. Check tenant status
	tenant, err := s.tenantRepo.FindByID(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get tenant", err, logger.String("tenant_id", req.TenantID))
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "failed to get tenant")
	}
	if tenant == nil {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "tenant not found", "")
	}
	if tenant.Status != constants.TenantStatusActive {
		s.logger.Warn(ctx, "Tenant is not active", logger.String("tenant_id", req.TenantID), logger.String("status", string(tenant.Status)))
		return nil, errors.New(errors.ErrCodeInvalidRequest, "tenant is not active", "")
	}

	// 4. Check rate limit
	rateLimitKey := fmt.Sprintf("mgr:%s:register", req.ClientID)
	allowed, _, _, err := s.rateLimitService.Allow(ctx, "mgr", rateLimitKey, "register")
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", err, logger.String("key", rateLimitKey))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to check rate limit")
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for MGR", logger.String("mgr_client_id", req.ClientID))
		return nil, errors.New(errors.ErrCodeRateLimitExceeded, "rate limit exceeded for MGR", "")
	}

	// 5. Check if device already exists and handle logic
	existingDevice, err := s.deviceRepo.FindByID(ctx, req.AgentID)
	if err != nil && !errors.IsNotFoundError(err) {
		s.logger.Error(ctx, "Failed to check device existence", err, logger.String("agent_id", req.AgentID))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to check device existence")
	}

	if existingDevice != nil {
		// Device already registered, verify fingerprint
		if existingDevice.DeviceFingerprint != req.DeviceFingerprint {
			s.logger.Warn(ctx, "Device fingerprint mismatch", logger.String("agent_id", req.AgentID))
			return nil, errors.New(errors.ErrCodeInvalidRequest, "device fingerprint mismatch", "")
		}
		s.logger.Info(ctx, "Device already registered, proceeding to issue token", logger.String("agent_id", req.AgentID))
	} else {
		// Device not found, create a new one
		device := &models.Device{
			DeviceID:          req.AgentID,
			TenantID:          req.TenantID,
			DeviceFingerprint: req.DeviceFingerprint,
			Status:            constants.DeviceStatusActive,
			RegisteredAt:      time.Now(),
			LastSeenAt:        time.Now(),
		}

		if err := s.deviceRepo.Save(ctx, device); err != nil {
			s.logger.Error(ctx, "Failed to create device", err, logger.String("agent_id", req.AgentID))
			return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to create device")
		}
		s.logger.Info(ctx, "New device registered successfully", logger.String("agent_id", req.AgentID))
	}

	// 6. Issue token pair
	refreshToken, accessToken, err := s.tokenService.IssueTokenPair(ctx, req.TenantID, req.AgentID, req.DeviceFingerprint, nil, nil)
	if err != nil {
		s.logger.Error(ctx, "Failed to issue token pair", err, logger.String("agent_id", req.AgentID))
		return nil, err // Propagate domain service error
	}

	// Defensive check on tokens
	if refreshToken == nil || accessToken == nil {
		return nil, errors.New(errors.ErrCodeInternal, "token service returned nil tokens without error", "")
	}

	// 7. Log and return response
	s.logger.Info(ctx, "Device registration and token issuance successful",
		logger.String("tenant_id", req.TenantID),
		logger.String("agent_id", req.AgentID),
	)

	return &dto.TokenResponse{
		AccessToken:  accessToken.JTI,
		RefreshToken: refreshToken.JTI,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessToken.TimeUntilExpiry().Seconds()),
		Scope:        accessToken.Scope,
		IssuedAt:     accessToken.IssuedAt.Unix(),
	}, nil
}

// IssueToken implements token issuance for an authenticated device
func (s *authAppServiceImpl) IssueToken(ctx context.Context, req *dto.IssueTokenRequest) (*dto.TokenResponse, error) {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid issue token request", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid issue token request")
	}

	// Check tenant status
	tenant, err := s.tenantRepo.FindByID(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get tenant", err, logger.String("tenant_id", req.TenantID))
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "failed to get tenant")
	}

	if tenant.Status != constants.TenantStatusActive {
		s.logger.Warn(ctx, "Tenant is not active", logger.String("tenant_id", req.TenantID), logger.String("status", string(tenant.Status)))
		return nil, errors.New(errors.ErrCodeInvalidRequest, "tenant is not active", "")
	}

	// Check rate limit for agent
	rateLimitKey := fmt.Sprintf("agent:%s:issue", req.AgentID)
	allowed, _, _, err := s.rateLimitService.Allow(ctx, "agent", rateLimitKey, "issue")
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", err, logger.String("key", rateLimitKey))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to check rate limit")
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for agent", logger.String("agent_id", req.AgentID))
		return nil, errors.New(errors.ErrCodeRateLimitExceeded, "rate limit exceeded for agent", "")
	}

	// Get device information
	device, err := s.deviceRepo.FindByID(ctx, req.AgentID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", req.AgentID))
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "failed to get device")
	}

	if device.Status != constants.DeviceStatusActive {
		s.logger.Warn(ctx, "Device is not active", logger.String("agent_id", req.AgentID), logger.String("status", string(device.Status)))
		return nil, errors.New(errors.ErrCodeInvalidRequest, "device is not active", "")
	}

	// Issue token pair using domain service
	refreshToken, accessToken, err := s.tokenService.IssueTokenPair(ctx, req.TenantID, req.AgentID, device.DeviceFingerprint, nil, nil)
	if err != nil {
		s.logger.Error(ctx, "Failed to issue token pair", err, logger.String("agent_id", req.AgentID))
		return nil, err
	}

	// Update device last seen time
	device.LastSeenAt = time.Now()
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Warn(ctx, "Failed to update device last seen time", logger.Error(err))
		// Don't fail the request if last seen update fails
	}

	// Record audit log
	s.logger.Info(ctx, "Token issuance successful",
		logger.String("tenant_id", req.TenantID),
		logger.String("agent_id", req.AgentID),
	)

	return &dto.TokenResponse{
		AccessToken:  accessToken.JTI,
		RefreshToken: refreshToken.JTI,
		TokenType:    "Bearer",
		ExpiresIn:    int64(accessToken.TimeUntilExpiry().Seconds()),
		Scope:        accessToken.Scope,
		IssuedAt:     accessToken.IssuedAt.Unix(),
	}, nil
}

// RefreshToken implements token refresh using a valid refresh token
func (s *authAppServiceImpl) RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest) (*dto.TokenResponse, error) {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid refresh token request", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid refresh token request")
	}

	// Verify old refresh token
	refreshToken, err := s.tokenService.VerifyToken(ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to verify refresh token", err)
		return nil, errors.Wrap(err, errors.FromConstants(constants.ErrCodeInvalidGrant), "failed to verify refresh token")
	}

	// Check rate limit for agent
	rateLimitKey := fmt.Sprintf("agent:%s:refresh", refreshToken.DeviceID)
	allowed, _, _, err := s.rateLimitService.Allow(ctx, "agent", rateLimitKey, "refresh")
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", err, logger.String("key", rateLimitKey))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to check rate limit")
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for agent", logger.String("agent_id", refreshToken.DeviceID))
		return nil, errors.New(errors.ErrCodeRateLimitExceeded, "rate limit exceeded for agent", "")
	}

	// Check device validity
	device, err := s.deviceRepo.FindByID(ctx, refreshToken.DeviceID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", refreshToken.DeviceID))
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "failed to get device")
	}

	if device.Status != constants.DeviceStatusActive {
		s.logger.Warn(ctx, "Device is not active", logger.String("agent_id", refreshToken.DeviceID), logger.String("status", string(device.Status)))
		return nil, errors.New(errors.ErrCodeInvalidRequest, "device is not active", "")
	}

	// Refresh token using domain service (one-time token mechanism)
	newRefreshToken, newAccessToken, err := s.tokenService.RefreshToken(ctx, req.RefreshToken, nil)
	if err != nil {
		s.logger.Error(ctx, "Failed to refresh token", err, logger.String("agent_id", refreshToken.DeviceID))
		return nil, err
	}

	// Update device last seen time
	device.LastSeenAt = time.Now()
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Warn(ctx, "Failed to update device last seen time", logger.Error(err))
		// Don't fail the request if last seen update fails
	}

	// Record audit log
	s.logger.Info(ctx, "Token refresh successful",
		logger.String("tenant_id", refreshToken.TenantID),
		logger.String("agent_id", refreshToken.DeviceID),
		logger.String("old_jti", refreshToken.JTI),
	)

	return &dto.TokenResponse{
		AccessToken:  newAccessToken.JTI,
		RefreshToken: newRefreshToken.JTI,
		TokenType:    "Bearer",
		ExpiresIn:    int64(newAccessToken.TimeUntilExpiry().Seconds()),
		Scope:        newAccessToken.Scope,
		IssuedAt:     newAccessToken.IssuedAt.Unix(),
	}, nil
}

// RevokeToken implements token revocation
func (s *authAppServiceImpl) RevokeToken(ctx context.Context, req *dto.RevokeTokenRequest) error {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid revoke token request", err)
		return errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid revoke token request")
	}

	// Verify token to get claims
	token, err := s.tokenService.VerifyToken(ctx, req.Token, constants.TokenType(req.TokenTypeHint), req.TenantID)
	if err != nil {
		// If token is invalid or expired, consider it already revoked
		s.logger.Warn(ctx, "Token verification failed during revocation", logger.Error(err))
		return nil
	}

	// Revoke token using domain service
	if err := s.tokenService.RevokeToken(ctx, token.JTI, token.TenantID, req.Reason); err != nil {
		s.logger.Error(ctx, "Failed to revoke token", err, logger.String("jti", token.JTI))
		return err
	}

	// Record audit log
	s.logger.Info(ctx, "Token revocation successful",
		logger.String("tenant_id", token.TenantID),
		logger.String("agent_id", token.DeviceID),
		logger.String("jti", token.JTI),
		logger.String("token_type", string(token.TokenType)),
		logger.String("reason", req.Reason),
	)

	return nil
}

// IntrospectToken implements token introspection
func (s *authAppServiceImpl) IntrospectToken(ctx context.Context, token string) (*dto.TokenIntrospectionResponse, error) {
	// Verify token
	t, err := s.tokenService.VerifyToken(ctx, token, "", "")
	if err != nil {
		s.logger.Error(ctx, "Failed to verify token during introspection", err)
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	// Check if token is revoked
	isRevoked, err := s.tokenService.IsTokenRevoked(ctx, t.JTI)
	if err != nil {
		s.logger.Error(ctx, "Failed to check token revocation status", err, logger.String("jti", t.JTI))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to check token revocation status")
	}

	if isRevoked {
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	// Check token expiration
	if t.IsExpired() {
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	// Token is valid and active
	return &dto.TokenIntrospectionResponse{
		Active:    true,
		Scope:     t.Scope,
		ClientID:  t.DeviceID,
		TenantID:  t.TenantID,
		Exp:       t.ExpiresAt.Unix(),
		Iat:       t.IssuedAt.Unix(),
		Jti:       t.JTI,
		TokenType: string(t.TokenType),
	}, nil
}
