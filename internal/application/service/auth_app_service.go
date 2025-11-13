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

//go:generate mockery --name AuthAppService --output ../../domain/service/mocks --outpkg mocks

// AuthAppService defines the application service interface for authentication-related use cases.
// It orchestrates domain services and repositories to handle operations like token issuance, refresh, and device registration.
// AuthAppService 定义了与身份验证相关的用例的应用程序服务接口。
// 它协调领域服务和存储库来处理令牌颁发、刷新和设备注册等操作。
type AuthAppService interface {
	// IssueToken issues a new token pair (access and refresh) for a pre-registered device.
	// IssueToken 为预注册的设备颁发新的令牌对（访问和刷新）。
	IssueToken(ctx context.Context, req *dto.IssueTokenRequest) (*dto.TokenResponse, error)

	// RefreshToken exchanges a valid refresh token for a new token pair.
	// RefreshToken 使用有效的刷新令牌换取新的令牌对。
	RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest) (*dto.TokenResponse, error)

	// RevokeToken invalidates a specific token (either access or refresh).
	// RevokeToken 使特定令牌（访问或刷新）无效。
	RevokeToken(ctx context.Context, req *dto.RevokeTokenRequest) error

	// IntrospectToken checks the validity of a token and returns its metadata.
	// IntrospectToken 检查令牌的有效性并返回其元数据。
	IntrospectToken(ctx context.Context, token string) (*dto.TokenIntrospectionResponse, error)

	// RegisterDevice handles the registration of a new device and issues its first token pair.
	// RegisterDevice 处理新设备的注册并颁发其第一个令牌对。
	RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.TokenResponse, error)
}

// authAppServiceImpl is the concrete implementation of the AuthAppService interface.
// authAppServiceImpl 是 AuthAppService 接口的具体实现。
type authAppServiceImpl struct {
	tokenService      domainService.TokenService
	deviceRepo        repository.DeviceRepository
	tenantRepo        repository.TenantRepository
	rateLimitService  domainService.RateLimitService
	blacklist         domainService.TokenBlacklistStore
	auditService      domainService.AuditService
	riskOracle        domainService.RiskOracle
	policyEngine      domainService.PolicyEngine
	logger            logger.Logger
}

// NewAuthAppService creates a new instance of AuthAppService.
// It wires together the necessary domain services and repositories.
// NewAuthAppService 创建一个新的 AuthAppService 实例。
// 它将必要的领域服务和存储库连接在一起。
func NewAuthAppService(
	tokenService domainService.TokenService,
	deviceRepo repository.DeviceRepository,
	tenantRepo repository.TenantRepository,
	rateLimitService domainService.RateLimitService,
	blacklist domainService.TokenBlacklistStore,
	auditService domainService.AuditService,
	riskOracle domainService.RiskOracle,
	policyEngine domainService.PolicyEngine,
	log logger.Logger,
) AuthAppService {
	return &authAppServiceImpl{
		tokenService:     tokenService,
		deviceRepo:       deviceRepo,
		tenantRepo:       tenantRepo,
		rateLimitService: rateLimitService,
		blacklist:        blacklist,
		auditService:     auditService,
		riskOracle:       riskOracle,
		policyEngine:     policyEngine,
		logger:           log,
	}
}

// RegisterDevice handles the business logic for device registration.
// It validates the request, checks tenant status, enforces rate limits, creates a new device if it doesn't exist, and issues the initial token pair.
// RegisterDevice 处理设备注册的业务逻辑。
// 它验证请求，检查租户状态，强制执行速率限制，如果设备不存在则创建新设备，并颁发初始令牌对。
func (s *authAppServiceImpl) RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.TokenResponse, error) {
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid register device request", err)
		return nil, errors.ErrInvalidRequest("invalid register device request").WithCause(err)
	}

	if s.tenantRepo == nil || s.rateLimitService == nil || s.deviceRepo == nil || s.tokenService == nil {
		s.logger.Error(ctx, "Service dependencies are not initialized", nil)
		return nil, errors.ErrServerError("service dependencies not initialized")
	}

	tenant, err := s.tenantRepo.FindByID(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get tenant", err, logger.String("tenant_id", req.TenantID))
		return nil, errors.ErrInvalidRequest("failed to get tenant").WithCause(err)
	}
	if tenant == nil {
		return nil, errors.ErrTenantNotFound(req.TenantID)
	}
	if tenant.Status != constants.TenantStatusActive {
		s.logger.Warn(ctx, "Tenant is not active", logger.String("tenant_id", req.TenantID), logger.String("status", string(tenant.Status)))
		return nil, errors.ErrTenantSuspended(req.TenantID)
	}

	rateLimitKey := fmt.Sprintf("mgr:%s:register", req.ClientID)
	allowed, _, _, err := s.rateLimitService.Allow(ctx, "mgr", rateLimitKey, "register")
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", err, logger.String("key", rateLimitKey))
		return nil, errors.ErrServerError("failed to check rate limit").WithCause(err)
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for MGR", logger.String("mgr_client_id", req.ClientID))
		return nil, errors.ErrRateLimitExceeded("mgr", 0)
	}

	existingDevice, err := s.deviceRepo.FindByID(ctx, req.AgentID)
	if err != nil && !errors.IsNotFoundError(err) {
		s.logger.Error(ctx, "Failed to check device existence", err, logger.String("agent_id", req.AgentID))
		return nil, errors.ErrServerError("failed to check device existence").WithCause(err)
	}

	if existingDevice != nil {
		if existingDevice.DeviceFingerprint != req.DeviceFingerprint {
			s.logger.Warn(ctx, "Device fingerprint mismatch", logger.String("agent_id", req.AgentID))
			return nil, errors.ErrInvalidRequest("device fingerprint mismatch")
		}
		s.logger.Info(ctx, "Device already registered, proceeding to issue token", logger.String("agent_id", req.AgentID))
	} else {
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
			return nil, errors.ErrServerError("failed to create device").WithCause(err)
		}
		s.logger.Info(ctx, "New device registered successfully", logger.String("agent_id", req.AgentID))
		s.auditService.LogEvent(ctx, models.AuditEvent{
			EventType: "device.register",
			TenantID:  req.TenantID,
			Actor:     req.AgentID,
			Success:   true,
		})
	}

	refreshToken, accessToken, err := s.tokenService.IssueTokenPair(ctx, req.TenantID, req.AgentID, req.DeviceFingerprint, nil, nil)
	if err != nil {
		s.logger.Error(ctx, "Failed to issue token pair", err, logger.String("agent_id", req.AgentID))
		return nil, err
	}

	if refreshToken == nil || accessToken == nil {
		return nil, errors.ErrServerError("token service returned nil tokens without error")
	}

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

// IssueToken handles the business logic for issuing a new token pair to an already authenticated device.
// It validates the request, checks tenant and device status, enforces rate limits, and then issues the tokens.
// IssueToken 处理向已认证设备颁发新令牌对的业务逻辑。
// 它验证请求，检查租户和设备状态，强制执行速率限制，然后颁发令牌。
func (s *authAppServiceImpl) IssueToken(ctx context.Context, req *dto.IssueTokenRequest) (*dto.TokenResponse, error) {
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid issue token request", err)
		return nil, errors.ErrInvalidRequest("invalid issue token request").WithCause(err)
	}

	tenant, err := s.tenantRepo.FindByID(ctx, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get tenant", err, logger.String("tenant_id", req.TenantID))
		return nil, errors.ErrInvalidRequest("failed to get tenant").WithCause(err)
	}

	if tenant.Status != constants.TenantStatusActive {
		s.logger.Warn(ctx, "Tenant is not active", logger.String("tenant_id", req.TenantID), logger.String("status", string(tenant.Status)))
		return nil, errors.ErrTenantSuspended(req.TenantID)
	}

	rateLimitKey := fmt.Sprintf("agent:%s:issue", req.AgentID)
	allowed, _, _, err := s.rateLimitService.Allow(ctx, "agent", rateLimitKey, "issue")
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", err, logger.String("key", rateLimitKey))
		return nil, errors.ErrServerError("failed to check rate limit").WithCause(err)
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for agent", logger.String("agent_id", req.AgentID))
		return nil, errors.ErrRateLimitExceeded("agent", 0)
	}

	device, err := s.deviceRepo.FindByID(ctx, req.AgentID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", req.AgentID))
		return nil, errors.ErrDeviceNotFound(req.AgentID).WithCause(err)
	}

	if device.Status != constants.DeviceStatusActive {
		s.logger.Warn(ctx, "Device is not active", logger.String("agent_id", req.AgentID), logger.String("status", string(device.Status)))
		return nil, errors.ErrDeviceUntrusted(req.AgentID, string(device.Status))
	}

	refreshToken, accessToken, err := s.tokenService.IssueTokenPair(ctx, req.TenantID, req.AgentID, device.DeviceFingerprint, nil, nil)
	if err != nil {
		s.logger.Error(ctx, "Failed to issue token pair", err, logger.String("agent_id", req.AgentID))
		return nil, err
	}

	device.LastSeenAt = time.Now()
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Warn(ctx, "Failed to update device last seen time", logger.Error(err))
	}

	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "token.issue",
		TenantID:  req.TenantID,
		Actor:     req.AgentID,
		Success:   true,
	})
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

// RefreshToken handles the logic for refreshing a token pair.
// It verifies the old token, checks for revocation, enforces rate limits, checks device status, and then issues a new one-time-use token pair.
// RefreshToken 处理刷新令牌对的逻辑。
// 它验证旧令牌，检查撤销，强制执行速率限制，检查设备状态，然后颁发新的一次性令牌对。
func (s *authAppServiceImpl) RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest) (*dto.TokenResponse, error) {
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid refresh token request", err)
		return nil, errors.ErrInvalidRequest("invalid refresh token request").WithCause(err)
	}

	refreshToken, err := s.tokenService.VerifyToken(ctx, req.RefreshToken, constants.TokenTypeRefresh, req.TenantID)
	if err != nil {
		s.logger.Error(ctx, "Failed to verify refresh token", err)
		return nil, errors.ErrInvalidGrant("failed to verify refresh token").WithCause(err)
	}

	isRevoked, err := s.blacklist.IsRevoked(ctx, refreshToken.TenantID, refreshToken.JTI)
	if err != nil {
		s.logger.Error(ctx, "Failed to check token revocation status", err, logger.String("jti", refreshToken.JTI))
		return nil, errors.ErrServerError("failed to check token revocation status").WithCause(err)
	}
	if isRevoked {
		return nil, errors.ErrTokenRevoked(string(refreshToken.TokenType), refreshToken.JTI)
	}

	rateLimitKey := fmt.Sprintf("agent:%s:refresh", refreshToken.DeviceID)
	allowed, _, _, err := s.rateLimitService.Allow(ctx, "agent", rateLimitKey, "refresh")
	if err != nil {
		s.logger.Error(ctx, "Failed to check rate limit", err, logger.String("key", rateLimitKey))
		return nil, errors.ErrServerError("failed to check rate limit").WithCause(err)
	}
	if !allowed {
		s.logger.Warn(ctx, "Rate limit exceeded for agent", logger.String("agent_id", refreshToken.DeviceID))
		return nil, errors.ErrRateLimitExceeded("agent", 0)
	}

	device, err := s.deviceRepo.FindByID(ctx, refreshToken.DeviceID)
	if err != nil {
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", refreshToken.DeviceID))
		return nil, errors.ErrDeviceNotFound(refreshToken.DeviceID).WithCause(err)
	}

	if device.Status != constants.DeviceStatusActive {
		s.logger.Warn(ctx, "Device is not active", logger.String("agent_id", refreshToken.DeviceID), logger.String("status", string(device.Status)))
		return nil, errors.ErrDeviceUntrusted(refreshToken.DeviceID, string(device.Status))
	}

	// 2. Revoke Old Token
	err = s.blacklist.Revoke(ctx, refreshToken.TenantID, refreshToken.JTI, refreshToken.ExpiresAt)
	if err != nil {
		s.logger.Error(ctx, "Failed to revoke old refresh token", err, logger.String("jti", refreshToken.JTI))
		return nil, errors.ErrServerError("failed to revoke old refresh token").WithCause(err)
	}

	// 3. Assess Risk
	riskProfile, err := s.riskOracle.GetTenantRisk(ctx, refreshToken.TenantID, refreshToken.DeviceID)
	if err != nil {
		s.logger.Warn(ctx, "Failed to get tenant risk, defaulting to low trust", logger.Error(err))
		// Default to a profile that ensures low trust on error
		riskProfile = &models.TenantRiskProfile{AnomalyScore: 1.0}
	}
	trustLevel := s.policyEngine.EvaluateTrustLevel(ctx, riskProfile)

	// 4. Determine Token Parameters
	defaultTTL := 15 * time.Minute
	defaultScope := "agent:read agent:write"
	var newTTL time.Duration
	var newScope string

	switch trustLevel {
	case models.TrustLevelHigh:
		newTTL = defaultTTL
		newScope = defaultScope
	case models.TrustLevelMedium:
		newTTL = 5 * time.Minute
		newScope = defaultScope
	case models.TrustLevelLow:
		newTTL = 60 * time.Second
		newScope = "agent:read"
	default:
		newTTL = 60 * time.Second
		newScope = "" // No scope for unknown trust levels
	}

	// 5. Generate New Tokens
	newAccessToken, err := s.tokenService.GenerateAccessToken(ctx, refreshToken, &newTTL, newScope, string(trustLevel))
	if err != nil {
		s.logger.Error(ctx, "Failed to generate new access token", err, logger.String("agent_id", refreshToken.DeviceID))
		return nil, errors.ErrServerError("failed to generate new access token").WithCause(err)
	}

	newRefreshToken, err := s.tokenService.IssueToken(ctx, refreshToken.TenantID, refreshToken.DeviceID, nil)
	if err != nil {
		s.logger.Error(ctx, "Failed to issue new refresh token", err, logger.String("agent_id", refreshToken.DeviceID))
		return nil, errors.ErrServerError("failed to issue new refresh token").WithCause(err)
	}

	// 4. Save New Token Metadata
	// The token is already saved by the IssueToken method, so we don't need to do anything here.

	device.LastSeenAt = time.Now()
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Warn(ctx, "Failed to update device last seen time", logger.Error(err))
	}

	// 5. Audit
	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "token.refresh",
		TenantID:  refreshToken.TenantID,
		Actor:     refreshToken.DeviceID,
		Success:   true,
		Details:   fmt.Sprintf("New JTI: %s", newRefreshToken.JTI),
	})
	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "token.revoke",
		TenantID:  refreshToken.TenantID,
		Actor:     refreshToken.DeviceID,
		Success:   true,
		Details:   fmt.Sprintf("Old JTI: %s, Reason: rotation", refreshToken.JTI),
	})
	s.logger.Info(ctx, "Token refresh successful",
		logger.String("tenant_id", refreshToken.TenantID),
		logger.String("agent_id", refreshToken.DeviceID),
		logger.String("old_jti", refreshToken.JTI),
		logger.String("new_jti", newRefreshToken.JTI),
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

// RevokeToken handles the business logic for revoking a token.
// It verifies the token to get its claims, then adds it to the blacklist.
// RevokeToken 处理撤销令牌的业务逻辑。
// 它验证令牌以获取其声明，然后将其添加到黑名单中。
func (s *authAppServiceImpl) RevokeToken(ctx context.Context, req *dto.RevokeTokenRequest) error {
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid revoke token request", err)
		return errors.ErrInvalidRequest("invalid revoke token request").WithCause(err)
	}

	token, err := s.tokenService.VerifyToken(ctx, req.Token, constants.TokenType(req.TokenTypeHint), req.TenantID)
	if err != nil {
		s.logger.Warn(ctx, "Token verification failed during revocation", logger.Error(err))
		return nil
	}

	if err := s.blacklist.Revoke(ctx, token.TenantID, token.JTI, token.ExpiresAt); err != nil {
		s.logger.Error(ctx, "Failed to revoke token", err, logger.String("jti", token.JTI))
		return err
	}

	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "token.revoke",
		TenantID:  token.TenantID,
		Actor:     token.DeviceID,
		Success:   true,
		Details:   fmt.Sprintf("JTI: %s, Reason: %s", token.JTI, req.Reason),
	})
	s.logger.Info(ctx, "Token revocation successful",
		logger.String("tenant_id", token.TenantID),
		logger.String("agent_id", token.DeviceID),
		logger.String("jti", token.JTI),
		logger.String("token_type", string(token.TokenType)),
		logger.String("reason", req.Reason),
	)

	return nil
}

// IntrospectToken handles the token introspection logic according to RFC 7662.
// It verifies the token, checks its revocation status and expiration, and returns its state and metadata.
// IntrospectToken 根据 RFC 7662 处理令牌自省逻辑。
// 它验证令牌，检查其撤销状态和到期时间，并返回其状态和元数据。
func (s *authAppServiceImpl) IntrospectToken(ctx context.Context, token string) (*dto.TokenIntrospectionResponse, error) {
	t, err := s.tokenService.VerifyToken(ctx, token, "", "")
	if err != nil {
		s.logger.Error(ctx, "Failed to verify token during introspection", err)
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	isRevoked, err := s.blacklist.IsRevoked(ctx, t.TenantID, t.JTI)
	if err != nil {
		s.logger.Error(ctx, "Failed to check token revocation status", err, logger.String("jti", t.JTI))
		return nil, errors.ErrServerError("failed to check token revocation status").WithCause(err)
	}

	if isRevoked {
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

	if t.IsExpired() {
		return &dto.TokenIntrospectionResponse{
			Active: false,
		}, nil
	}

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
