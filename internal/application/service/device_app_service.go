// Package service provides application-level services for device management
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	domainService "github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

//go:generate mockery --name DeviceAppService --output ../../domain/service/mocks --outpkg mocks

// DeviceAppService defines the application service interface for device management use cases.
// It orchestrates domain services and repositories to handle device-related operations.
// DeviceAppService 定义了设备管理用例的应用程序服务接口。
// 它协调领域服务和存储库来处理与设备相关的操作。
type DeviceAppService interface {
	// RegisterDevice registers a new device in the system after verifying the MGR client assertion.
	// RegisterDevice 在验证 MGR 客户端断言后在系统中注册一个新设备。
	RegisterDevice(ctx context.Context, req *dto.DeviceRegisterRequest) (*dto.DeviceResponse, error)

	// GetDeviceInfo retrieves detailed information for a specific device by its agent ID.
	// GetDeviceInfo 通过其代理 ID 检索特定设备的详细信息。
	GetDeviceInfo(ctx context.Context, agentID string) (*dto.DeviceResponse, error)

	// UpdateDeviceInfo updates mutable information for an existing device.
	// UpdateDeviceInfo 更新现有设备的可变信息。
	UpdateDeviceInfo(ctx context.Context, agentID string, req *dto.DeviceUpdateRequest) (*dto.DeviceResponse, error)

	// UpdateDeviceTrustLevel manually sets the trust level for a device.
	// UpdateDeviceTrustLevel 手动设置设备的信任级别。
	UpdateDeviceTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error

	// DeactivateDevice deactivates a device, preventing it from authenticating.
	// DeactivateDevice 停用设备，阻止其进行身份验证。
	DeactivateDevice(ctx context.Context, agentID string, reason string) error

	// ListDevicesByTenant retrieves a paginated list of all devices belonging to a specific tenant.
	// ListDevicesByTenant 检索属于特定租户的所有设备的分页列表。
	ListDevicesByTenant(ctx context.Context, tenantID string, page, pageSize int) ([]*dto.DeviceResponse, int64, error)

	// VerifyDeviceFingerprint checks if a provided fingerprint matches the one stored for the device.
	// VerifyDeviceFingerprint 检查提供的指纹是否与为设备存储的指纹匹配。
	VerifyDeviceFingerprint(ctx context.Context, agentID, fingerprint string) (bool, error)
}

// deviceAppServiceImpl is the concrete implementation of the DeviceAppService interface.
// deviceAppServiceImpl 是 DeviceAppService 接口的具体实现。
type deviceAppServiceImpl struct {
	deviceRepo    repository.DeviceRepository
	auditService  domainService.AuditService
	mgrKeyFetcher domainService.MgrKeyFetcher
	policyService domainService.PolicyService
	tokenService  domainService.TokenService
	blacklist     domainService.TokenBlacklistStore
	cfg           *config.Config
	logger        logger.Logger
}

// NewDeviceAppService creates a new instance of DeviceAppService, injecting its dependencies.
// NewDeviceAppService 创建一个新的 DeviceAppService 实例，并注入其依赖项。
func NewDeviceAppService(
	deviceRepo repository.DeviceRepository,
	auditService domainService.AuditService,
	mgrKeyFetcher domainService.MgrKeyFetcher,
	policyService domainService.PolicyService,
	tokenService domainService.TokenService,
	blacklist domainService.TokenBlacklistStore,
	cfg *config.Config,
	log logger.Logger,
) DeviceAppService {
	return &deviceAppServiceImpl{
		deviceRepo:    deviceRepo,
		auditService:  auditService,
		mgrKeyFetcher: mgrKeyFetcher,
		policyService: policyService,
		tokenService:  tokenService,
		blacklist:     blacklist,
		cfg:           cfg,
		logger:        log,
	}
}

// RegisterDevice handles the logic for registering a new device.
// It verifies the MGR assertion, checks for existing devices, evaluates trust level, saves the new device, and issues an initial token.
// RegisterDevice 处理注册新设备的逻辑。
// 它验证 MGR 断言，检查现有设备，评估信任级别，保存新设备，并颁发初始令牌。
func (s *deviceAppServiceImpl) RegisterDevice(ctx context.Context, req *dto.DeviceRegisterRequest) (*dto.DeviceResponse, error) {
	if err := s.verifyMgrClientAssertion(ctx, req.ClientAssertion, req.ClientID); err != nil {
		return nil, err
	}

	existingDevice, err := s.deviceRepo.FindByID(ctx, req.AgentID)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to check device existence")
	}
	if existingDevice != nil {
		return nil, errors.New(errors.ErrCodeConflict, "device already exists", "")
	}

	trustLevel, err := s.policyService.EvaluateTrustLevel(ctx, req.DeviceFingerprint)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to evaluate trust level")
	}

	device := &models.Device{
		DeviceID:          req.AgentID,
		TenantID:          req.TenantID,
		DeviceFingerprint: req.DeviceFingerprint,
		DeviceName:        req.DeviceName,
		DeviceType:        constants.DeviceType(req.DeviceType),
		TrustLevel:        constants.TrustLevel(trustLevel),
		Status:            constants.DeviceStatusActive,
		RegisteredAt:      time.Now(),
		LastSeenAt:        time.Now(),
	}

	if err := s.deviceRepo.Save(ctx, device); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to create device")
	}

	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "device.register",
		TenantID:  req.TenantID,
		Actor:     req.AgentID,
		Success:   true,
		Details:   fmt.Sprintf("Device Type: %s, Trust Level: %s", req.DeviceType, device.TrustLevel),
	})

	refreshToken, _, err := s.tokenService.IssueTokenPair(ctx, device.TenantID, device.DeviceID, device.DeviceFingerprint, []string{"device"}, map[string]interface{}{"trust_level": trustLevel})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to issue refresh token")
	}

	return s.deviceToResponse(device, refreshToken.JTI), nil
}

// GetDeviceInfo retrieves and returns the information for a specific device.
// GetDeviceInfo 检索并返回特定设备的信息。
func (s *deviceAppServiceImpl) GetDeviceInfo(ctx context.Context, agentID string) (*dto.DeviceResponse, error) {
	if agentID == "" {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "agent_id is required", "")
	}

	device, err := s.deviceRepo.FindByID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			s.logger.Warn(ctx, "Device not found", logger.String("agent_id", agentID))
			return nil, errors.New(errors.ErrCodeNotFound, "device not found", "")
		}
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", agentID))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get device")
	}

	return s.deviceToResponse(device), nil
}

// UpdateDeviceInfo updates the mutable properties of a device.
// UpdateDeviceInfo 更新设备的可变属性。
func (s *deviceAppServiceImpl) UpdateDeviceInfo(ctx context.Context, agentID string, req *dto.DeviceUpdateRequest) (*dto.DeviceResponse, error) {
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid update device request", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid update device request")
	}

	device, err := s.deviceRepo.FindByID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			s.logger.Warn(ctx, "Device not found", logger.String("agent_id", agentID))
			return nil, errors.New(errors.ErrCodeNotFound, "device not found", "")
		}
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", agentID))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get device")
	}

	if req.DeviceName != "" {
		device.DeviceName = req.DeviceName
	}
	device.LastSeenAt = time.Now()

	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to update device", err, logger.String("agent_id", agentID))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to update device")
	}

	s.logger.Info(ctx, "Device updated successfully", logger.String("agent_id", agentID))
	return s.deviceToResponse(device), nil
}

// UpdateDeviceTrustLevel sets a new trust level for a device.
// UpdateDeviceTrustLevel 为设备设置新的信任级别。
func (s *deviceAppServiceImpl) UpdateDeviceTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error {
	if agentID == "" {
		return errors.New(errors.CodeInvalidArgument, "agent_id is required")
	}

	switch trustLevel {
	case constants.TrustLevelHigh, constants.TrustLevelMedium, constants.TrustLevelLow, constants.TrustLevelUntrusted:
	default:
		return errors.New(errors.CodeInvalidArgument, "invalid trust level")
	}

	device, err := s.deviceRepo.FindByID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return errors.New(errors.CodeNotFound, "device not found")
		}
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", agentID))
		return errors.Wrap(err, errors.CodeInternal, "failed to get device")
	}

	oldTrustLevel := device.TrustLevel
	device.TrustLevel = trustLevel

	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to update device trust level", err, logger.String("agent_id", agentID))
		return errors.Wrap(err, errors.CodeInternal, "failed to update device trust level")
	}

	s.logger.Info(ctx, "Device trust level updated",
		logger.String("agent_id", agentID),
		logger.String("old_trust_level", string(oldTrustLevel)),
		logger.String("new_trust_level", string(trustLevel)),
	)
	return nil
}

// DeactivateDevice marks a device as inactive.
// DeactivateDevice 将设备标记为非活动状态。
func (s *deviceAppServiceImpl) DeactivateDevice(ctx context.Context, agentID string, reason string) error {
	if agentID == "" {
		return errors.New(errors.CodeInvalidArgument, "agent_id is required")
	}

	device, err := s.deviceRepo.FindByID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return errors.New(errors.CodeNotFound, "device not found")
		}
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", agentID))
		return errors.Wrap(err, errors.CodeInternal, "failed to get device")
	}

	if device.Status == constants.DeviceStatusInactive {
		s.logger.Warn(ctx, "Device already inactive", logger.String("agent_id", agentID))
		return nil
	}

	device.Status = constants.DeviceStatusInactive

	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to deactivate device", err, logger.String("agent_id", agentID))
		return errors.Wrap(err, errors.CodeInternal, "failed to deactivate device")
	}

	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "device.deactivate",
		TenantID:  device.TenantID,
		Actor:     agentID,
		Success:   true,
		Details:   fmt.Sprintf("Reason: %s", reason),
	})
	s.logger.Info(ctx, "Device deactivated",
		logger.String("agent_id", agentID),
		logger.String("reason", reason),
	)
	return nil
}

// ListDevicesByTenant retrieves a paginated list of devices for a given tenant.
// ListDevicesByTenant 检索给定租户的设备分页列表。
func (s *deviceAppServiceImpl) ListDevicesByTenant(ctx context.Context, tenantID string, page, pageSize int) ([]*dto.DeviceResponse, int64, error) {
	if tenantID == "" {
		return nil, 0, errors.New(errors.CodeInvalidArgument, "tenant_id is required")
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	devices, total, err := s.deviceRepo.FindByTenantID(ctx, tenantID, page, pageSize)
	if err != nil {
		s.logger.Error(ctx, "Failed to list devices", err, logger.String("tenant_id", tenantID))
		return nil, 0, errors.Wrap(err, errors.CodeInternal, "failed to list devices")
	}

	responses := make([]*dto.DeviceResponse, len(devices))
	for i, device := range devices {
		responses[i] = s.deviceToResponse(device)
	}

	return responses, total, nil
}

// VerifyDeviceFingerprint compares a provided fingerprint with the one stored for the device.
// VerifyDeviceFingerprint 将提供的指纹与为设备存储的指纹进行比较。
func (s *deviceAppServiceImpl) VerifyDeviceFingerprint(ctx context.Context, agentID, fingerprint string) (bool, error) {
	if agentID == "" || fingerprint == "" {
		return false, errors.New(errors.CodeInvalidArgument, "agent_id and fingerprint are required")
	}

	device, err := s.deviceRepo.FindByID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, errors.New(errors.CodeNotFound, "device not found")
		}
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", agentID))
		return false, errors.Wrap(err, errors.CodeInternal, "failed to get device")
	}

	matches := device.DeviceFingerprint == fingerprint
	if !matches {
		s.logger.Warn(ctx, "Device fingerprint mismatch",
			logger.String("agent_id", agentID),
			logger.String("expected", device.DeviceFingerprint),
			logger.String("provided", fingerprint),
		)
	}
	return matches, nil
}

// generateDeviceFingerprint generates a device fingerprint hash
func (s *deviceAppServiceImpl) generateDeviceFingerprint(req *dto.DeviceRegisterRequest) string {
	data := fmt.Sprintf("%s:%s",
		req.AgentID,
		req.DeviceType,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// calculateInitialTrustLevel calculates initial trust level based on device information
func (s *deviceAppServiceImpl) calculateInitialTrustLevel(req *dto.DeviceRegisterRequest) constants.TrustLevel {
	// Default trust level is medium
	trustLevel := constants.TrustLevelMedium

	// If device has strong fingerprint (e.g., TPM/TEE binding), set high trust
	// This is a simplified logic, real implementation would check actual hardware features
	if req.DeviceFingerprint != "" && len(req.DeviceFingerprint) >= 64 {
		trustLevel = constants.TrustLevelHigh
	}

	return trustLevel
}

// deviceToResponse converts device model to response DTO
func (s *deviceAppServiceImpl) deviceToResponse(device *models.Device, refreshToken ...string) *dto.DeviceResponse {
	resp := &dto.DeviceResponse{
		AgentID:           device.DeviceID,
		TenantID:          device.TenantID,
		DeviceFingerprint: device.DeviceFingerprint,
		DeviceName:        device.DeviceName,
		DeviceType:        string(device.DeviceType),
		TrustLevel:        string(device.TrustLevel),
		Status:            string(device.Status),
		RegisteredAt:      device.RegisteredAt,
		LastSeenAt:        device.LastSeenAt,
	}
	if len(refreshToken) > 0 {
		resp.RefreshToken = refreshToken[0]
	}
	return resp
}

func (s *deviceAppServiceImpl) verifyMgrClientAssertion(ctx context.Context, assertion, clientID string) error {
	// 1. Unverified Parse to get kid
	token, _, err := new(jwt.Parser).ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return errors.ErrInvalidGrant("failed to parse client assertion")
	}
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return errors.ErrInvalidGrant("missing 'kid' in client assertion header")
	}

	// 2. Fetch MGR Public Key
	publicKey, err := s.mgrKeyFetcher.GetMgrPublicKey(ctx, clientID, kid)
	if err != nil {
		return errors.ErrInvalidGrant("failed to fetch MGR public key")
	}

	// 3. Verified Parse
	parsedToken, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		return errors.ErrInvalidGrant("client assertion validation failed")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		return errors.ErrInvalidGrant("invalid client assertion claims")
	}

	// 4. Validate Claims (iss, aud, exp)
	if iss, err := claims.GetIssuer(); err != nil || iss != clientID {
		return errors.ErrInvalidGrant("invalid 'iss' in client assertion")
	}

	if aud, err := claims.GetAudience(); err != nil || !s.isValidAudience(aud) {
		return errors.ErrInvalidGrant("invalid 'aud' in client assertion")
	}

	if exp, err := claims.GetExpirationTime(); err != nil || exp.Time.Before(time.Now()) {
		return errors.ErrInvalidGrant("client assertion has expired")
	}

	// 5. Prevent Replay Attacks with JTI
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return errors.ErrInvalidGrant("missing 'jti' in client assertion")
	}

	// The tenantID for the blacklist should be the one from the request.
	tenantID, _ := claims["tenant_id"].(string)
	isRevoked, err := s.blacklist.IsRevoked(ctx, tenantID, jti)
	if err != nil {
		return errors.ErrServerError("failed to check JTI replay")
	}
	if isRevoked {
		return errors.ErrInvalidGrant("JTI has been replayed")
	}
	exp, _ := claims.GetExpirationTime()
	if err := s.blacklist.Revoke(ctx, tenantID, jti, exp.Time); err != nil {
		s.logger.Error(ctx, "failed to store JTI for replay prevention", err, logger.String("jti", jti))
		// Continue even if storing JTI fails, as the assertion is otherwise valid.
	}

	return nil
}

func (s *deviceAppServiceImpl) isValidAudience(aud jwt.ClaimStrings) bool {
	for _, a := range aud {
		if a == s.cfg.Server.IssuerURL {
			return true
		}
	}
	return false
}
