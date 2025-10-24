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
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid register device request", "error", err)
		return nil, errors.ErrInvalidRequest.Wrap(err)
	}

	// Check tenant status
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get tenant", "tenant_id", req.TenantID, "error", err)
		return nil, errors.ErrTenantNotFound.Wrap(err)
	}

	if tenant.Status != models.TenantStatusActive {
		s.logger.Warn(ctx, "Tenant is not active", "tenant_id", req.TenantID, "status", tenant.Status)
		return nil, errors.ErrTenantInactive
	}

	// Check rate limit for MGR
	rateLimitKey := fmt.Sprintf("mgr:%s:register", req.MgrClientID)
	allowed, err := s.rateLimitService.AllowRequest(ctx, rateLimitKey, 100, time.Minute)
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", "key", rateLimitKey, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for MGR", "mgr_client_id", req.MgrClientID)
		return nil, errors.ErrRateLimitExceeded
	}

	// Check if device already exists
	existingDevice, err := s.deviceRepo.GetByAgentID(ctx, req.AgentID)
	if err != nil && !errors.IsNotFoundError(err) {
		s.logger.Error(ctx, "Failed to check device existence", "agent_id", req.AgentID, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}

	if existingDevice != nil {
		// Device already registered, check device fingerprint
		if existingDevice.DeviceFingerprint != req.DeviceFingerprint {
			s.logger.Warn(ctx, "Device fingerprint mismatch", "agent_id", req.AgentID)
			return nil, errors.ErrDeviceFingerprintMismatch
		}

		// Return existing refresh token if still valid
		s.logger.Info(ctx, "Device already registered, returning existing token", "agent_id", req.AgentID)
	} else {
		// Create new device
		device := &models.Device{
			AgentID:           req.AgentID,
			TenantID:          req.TenantID,
			DeviceFingerprint: req.DeviceFingerprint,
			DeviceName:        req.DeviceName,
			DeviceType:        req.DeviceType,
			TrustLevel:        models.TrustLevelHigh,
			Status:            models.DeviceStatusActive,
			RegisteredAt:      time.Now(),
			LastSeenAt:        time.Now(),
			IPAddress:         req.IPAddress,
			UserAgent:         req.UserAgent,
		}

		if err := s.deviceRepo.Create(ctx, device); err != nil {
			s.logger.Error(ctx, "Failed to create device", "agent_id", req.AgentID, "error", err)
			return nil, errors.ErrInternalServer.Wrap(err)
		}

		s.logger.Info(ctx, "Device registered successfully", "agent_id", req.AgentID)
	}

	// Issue token pair using domain service
	tokenPair, err := s.tokenService.IssueTokenPair(ctx, &domainService.TokenRequest{
		TenantID:    req.TenantID,
		AgentID:     req.AgentID,
		Scope:       req.Scope,
		DeviceInfo:  req.DeviceFingerprint,
		TrustLevel:  models.TrustLevelHigh,
		IPAddress:   req.IPAddress,
		UserAgent:   req.UserAgent,
	})
	if err != nil {
		s.logger.Error(ctx, "Failed to issue token pair", "agent_id", req.AgentID, "error", err)
		return nil, err
	}

	// Record audit log
	s.logger.Info(ctx, "Device registration and token issuance successful",
		"tenant_id", req.TenantID,
		"agent_id", req.AgentID,
		"mgr_client_id", req.MgrClientID,
	)

	return &dto.TokenResponse{
		AccessToken:           tokenPair.AccessToken,
		RefreshToken:          tokenPair.RefreshToken,
		TokenType:             "Bearer",
		ExpiresIn:             int(tokenPair.AccessTokenExpiresIn.Seconds()),
		RefreshTokenExpiresIn: int(tokenPair.RefreshTokenExpiresIn.Seconds()),
		Scope:                 tokenPair.Scope,
	}, nil
}

// IssueToken implements token issuance for an authenticated device
func (s *authAppServiceImpl) IssueToken(ctx context.Context, req *dto.IssueTokenRequest) (*dto.TokenResponse, error) {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid issue token request", "error", err)
		return nil, errors.ErrInvalidRequest.Wrap(err)
	}

	// Check tenant status
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get tenant", "tenant_id", req.TenantID, "error", err)
		return nil, errors.ErrTenantNotFound.Wrap(err)
	}

	if tenant.Status != models.TenantStatusActive {
		s.logger.Warn(ctx, "Tenant is not active", "tenant_id", req.TenantID, "status", tenant.Status)
		return nil, errors.ErrTenantInactive
	}

	// Check rate limit for agent
	rateLimitKey := fmt.Sprintf("agent:%s:issue", req.AgentID)
	allowed, err := s.rateLimitService.AllowRequest(ctx, rateLimitKey, 10, time.Minute)
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", "key", rateLimitKey, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for agent", "agent_id", req.AgentID)
		return nil, errors.ErrRateLimitExceeded
	}

	// Get device information
	device, err := s.deviceRepo.GetByAgentID(ctx, req.AgentID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get device", "agent_id", req.AgentID, "error", err)
		return nil, errors.ErrDeviceNotFound.Wrap(err)
	}

	if device.Status != models.DeviceStatusActive {
		s.logger.Warn(ctx, "Device is not active", "agent_id", req.AgentID, "status", device.Status)
		return nil, errors.ErrDeviceInactive
	}

	// Issue token pair using domain service
	tokenPair, err := s.tokenService.IssueTokenPair(ctx, &domainService.TokenRequest{
		TenantID:   req.TenantID,
		AgentID:    req.AgentID,
		Scope:      req.Scope,
		DeviceInfo: device.DeviceFingerprint,
		TrustLevel: device.TrustLevel,
		IPAddress:  req.IPAddress,
		UserAgent:  req.UserAgent,
	})
	if err != nil {
		s.logger.Error(ctx, "Failed to issue token pair", "agent_id", req.AgentID, "error", err)
		return nil, err
	}

	// Update device last seen time
	device.LastSeenAt = time.Now()
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Warn(ctx, "Failed to update device last seen time", "agent_id", req.AgentID, "error", err)
		// Don't fail the request if last seen update fails
	}

	// Record audit log
	s.logger.Info(ctx, "Token issuance successful",
		"tenant_id", req.TenantID,
		"agent_id", req.AgentID,
	)

	return &dto.TokenResponse{
		AccessToken:           tokenPair.AccessToken,
		RefreshToken:          tokenPair.RefreshToken,
		TokenType:             "Bearer",
		ExpiresIn:             int(tokenPair.AccessTokenExpiresIn.Seconds()),
		RefreshTokenExpiresIn: int(tokenPair.RefreshTokenExpiresIn.Seconds()),
		Scope:                 tokenPair.Scope,
	}, nil
}

// RefreshToken implements token refresh using a valid refresh token
func (s *authAppServiceImpl) RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest) (*dto.TokenResponse, error) {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid refresh token request", "error", err)
		return nil, errors.ErrInvalidRequest.Wrap(err)
	}

	// Verify old refresh token
	claims, err := s.tokenService.VerifyToken(ctx, req.RefreshToken)
	if err != nil {
		s.logger.Error(ctx, "Failed to verify refresh token", "error", err)
		return nil, errors.ErrInvalidToken.Wrap(err)
	}

	// Verify token type
	if claims.TokenType != models.TokenTypeRefresh {
		s.logger.Warn(ctx, "Invalid token type for refresh", "token_type", claims.TokenType)
		return nil, errors.ErrInvalidTokenType
	}

	// Check rate limit for agent
	rateLimitKey := fmt.Sprintf("agent:%s:refresh", claims.AgentID)
	allowed, err := s.rateLimitService.AllowRequest(ctx, rateLimitKey, 10, time.Minute)
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", "key", rateLimitKey, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for agent", "agent_id", claims.AgentID)
		return nil, errors.ErrRateLimitExceeded
	}

	// Check device validity
	device, err := s.deviceRepo.GetByAgentID(ctx, claims.AgentID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get device", "agent_id", claims.AgentID, "error", err)
		return nil, errors.ErrDeviceNotFound.Wrap(err)
	}

	if device.Status != models.DeviceStatusActive {
		s.logger.Warn(ctx, "Device is not active", "agent_id", claims.AgentID, "status", device.Status)
		return nil, errors.ErrDeviceInactive
	}

	// Refresh token using domain service (one-time token mechanism)
	newTokenPair, err := s.tokenService.RefreshToken(ctx, claims)
	if err != nil {
		s.logger.Error(ctx, "Failed to refresh token", "agent_id", claims.AgentID, "error", err)
		return nil, err
	}

	// Update device last seen time
	device.LastSeenAt = time.Now()
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Warn(ctx, "Failed to update device last seen time", "agent_id", claims.AgentID, "error", err)
		// Don't fail the request if last seen update fails
	}

	// Record audit log
	s.logger.Info(ctx, "Token refresh successful",
		"tenant_id", claims.TenantID,
		"agent_id", claims.AgentID,
		"old_jti", claims.JTI,
	)

	return &dto.TokenResponse{
		AccessToken:           newTokenPair.AccessToken,
		RefreshToken:          newTokenPair.RefreshToken,
		TokenType:             "Bearer",
		ExpiresIn:             int(newTokenPair.AccessTokenExpiresIn.Seconds()),
		RefreshTokenExpiresIn: int(newTokenPair.RefreshTokenExpiresIn.Seconds()),
		Scope:                 newTokenPair.Scope,
	}, nil
}

// RevokeToken implements token revocation
func (s *authAppServiceImpl) RevokeToken(ctx context.Context, req *dto.RevokeTokenRequest) error {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid revoke token request", "error", err)
		return errors.ErrInvalidRequest.Wrap(err)
	}

	// Verify token to get claims
	claims, err := s.tokenService.VerifyToken(ctx, req.Token)
	if err != nil {
		// If token is invalid or expired, consider it already revoked
		s.logger.Warn(ctx, "Token verification failed during revocation", "error", err)
		return nil
	}

	// Revoke token using domain service
	if err := s.tokenService.RevokeToken(ctx, claims); err != nil {
		s.logger.Error(ctx, "Failed to revoke token", "jti", claims.JTI, "error", err)
		return err
	}

	// Record audit log
	s.logger.Info(ctx, "Token revocation successful",
		"tenant_id", claims.TenantID,
		"agent_id", claims.AgentID,
		"jti", claims.JTI,
		"token_type", claims.TokenType,
		"reason", req.Reason,
	)

	return nil
}

// IntrospectToken implements token introspection
func (s *authAppServiceImpl) IntrospectToken(ctx context.Context, token string) (*dto.TokenIntrospectionResponse, error) {
	// Verify token
	claims, err := s.tokenService.VerifyToken(ctx, token)
	if err != nil {
		s.logger.Error(ctx, "Failed to verify token during introspection", "error", err)
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	// Check if token is revoked
	isRevoked, err := s.tokenService.IsTokenRevoked(ctx, claims.JTI)
	if err != nil {
		s.logger.Error(ctx, "Failed to check token revocation status", "jti", claims.JTI, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}

	if isRevoked {
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	// Check token expiration
	if time.Now().After(time.Unix(claims.ExpiresAt, 0)) {
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	// Token is valid and active
	return &dto.TokenIntrospectionResponse{
		Active:           true,
		Scope:            claims.Scope,
		ClientID:         claims.AgentID,
		TenantID:         claims.TenantID,
		ExpiresAt:        claims.ExpiresAt,
		IssuedAt:         claims.IssuedAt,
		Subject:          claims.Subject,
		JTI:              claims.JTI,
		TokenType:        string(claims.TokenType),
		DeviceTrustLevel: string(claims.DeviceTrustLevel),
	}, nil
}

//Personal.AI order the ending

