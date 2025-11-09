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
// DeviceAppService defines the interface for device application service
type DeviceAppService interface {
	// RegisterDevice registers a new device in the system
	RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.DeviceResponse, error)

	// GetDeviceInfo retrieves device information by agent ID
	GetDeviceInfo(ctx context.Context, agentID string) (*dto.DeviceResponse, error)

	// UpdateDeviceInfo updates device information
	UpdateDeviceInfo(ctx context.Context, agentID string, req *dto.UpdateDeviceRequest) (*dto.DeviceResponse, error)

	// UpdateDeviceTrustLevel updates device trust level
	UpdateDeviceTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error

	// DeactivateDevice deactivates a device
	DeactivateDevice(ctx context.Context, agentID string, reason string) error

	// ListDevicesByTenant lists all devices for a tenant
	ListDevicesByTenant(ctx context.Context, tenantID string, page, pageSize int) ([]*dto.DeviceResponse, int64, error)

	// VerifyDeviceFingerprint verifies if device fingerprint matches
	VerifyDeviceFingerprint(ctx context.Context, agentID, fingerprint string) (bool, error)
}

// deviceAppServiceImpl is the concrete implementation of DeviceAppService
type deviceAppServiceImpl struct {
	deviceRepo    repository.DeviceRepository
	auditService  domainService.AuditService
	mgrKeyFetcher domainService.MgrKeyFetcher
	policyService domainService.PolicyService
	tokenService  domainService.TokenService
	cfg           *config.Config
	logger        logger.Logger
}

// NewDeviceAppService creates a new instance of DeviceAppService
func NewDeviceAppService(
	deviceRepo repository.DeviceRepository,
	auditService domainService.AuditService,
	mgrKeyFetcher domainService.MgrKeyFetcher,
	policyService domainService.PolicyService,
	tokenService domainService.TokenService,
	cfg *config.Config,
	log logger.Logger,
) DeviceAppService {
	return &deviceAppServiceImpl{
		deviceRepo:    deviceRepo,
		auditService:  auditService,
		mgrKeyFetcher: mgrKeyFetcher,
		policyService: policyService,
		tokenService:  tokenService,
		cfg:           cfg,
		logger:        log,
	}
}

// RegisterDevice implements device registration
func (s *deviceAppServiceImpl) RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.DeviceResponse, error) {
	// 1. Verify MGR Client Assertion
	if err := s.verifyMgrClientAssertion(ctx, req.ClientAssertion, req.ClientID); err != nil {
		return nil, err
	}

	// 2. Check if device already exists
	existingDevice, err := s.deviceRepo.FindByID(ctx, req.AgentID)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to check device existence")
	}
	if existingDevice != nil {
		return nil, errors.New(errors.ErrCodeConflict, "device already exists", "")
	}

	// 3. Evaluate trust level
	trustLevel, err := s.policyService.EvaluateTrustLevel(ctx, req.DeviceFingerprint)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to evaluate trust level")
	}

	// 4. Create device model
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

	// 5. Save device to database
	if err := s.deviceRepo.Save(ctx, device); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to create device")
	}

	// 6. Record audit log
	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "device.register",
		TenantID:  req.TenantID,
		DeviceID:  req.AgentID,
		Success:   true,
		Details:   fmt.Sprintf("Device Type: %s, Trust Level: %s", req.DeviceType, device.TrustLevel),
	})

	// 7. Issue a refresh token
	refreshToken, _, err := s.tokenService.IssueTokenPair(ctx, device.TenantID, device.DeviceID, device.DeviceFingerprint, []string{"device"}, map[string]interface{}{"trust_level": trustLevel})
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to issue refresh token")
	}

	return s.deviceToResponse(device, refreshToken.JTI), nil
}

// GetDeviceInfo retrieves device information
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

// UpdateDeviceInfo updates device information
func (s *deviceAppServiceImpl) UpdateDeviceInfo(ctx context.Context, agentID string, req *dto.UpdateDeviceRequest) (*dto.DeviceResponse, error) {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid update device request", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRequest, "invalid update device request")
	}

	// Get existing device
	device, err := s.deviceRepo.FindByID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			s.logger.Warn(ctx, "Device not found", logger.String("agent_id", agentID))
			return nil, errors.New(errors.ErrCodeNotFound, "device not found", "")
		}
		s.logger.Error(ctx, "Failed to get device", err, logger.String("agent_id", agentID))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to get device")
	}

	// Update fields if provided
	if req.DeviceName != "" {
		device.DeviceName = req.DeviceName
	}
	// if req.Metadata != nil {
	// 	// device.Metadata = req.Metadata
	// }

	device.LastSeenAt = time.Now()

	// Save updated device
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to update device", err, logger.String("agent_id", agentID))
		return nil, errors.Wrap(err, errors.ErrCodeInternal, "failed to update device")
	}

	s.logger.Info(ctx, "Device updated successfully", logger.String("agent_id", agentID))

	return s.deviceToResponse(device), nil
}

// UpdateDeviceTrustLevel updates device trust level
func (s *deviceAppServiceImpl) UpdateDeviceTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error {
	if agentID == "" {
		return errors.New(errors.CodeInvalidArgument, "agent_id is required")
	}

	// Validate trust level
	switch trustLevel {
	case constants.TrustLevelHigh, constants.TrustLevelMedium, constants.TrustLevelLow, constants.TrustLevelUntrusted:
		// Valid trust level
	default:
		return errors.New(errors.CodeInvalidArgument, "invalid trust level")
	}

	// Get device
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

	// Save updated device
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

// DeactivateDevice deactivates a device
func (s *deviceAppServiceImpl) DeactivateDevice(ctx context.Context, agentID string, reason string) error {
	if agentID == "" {
		return errors.New(errors.CodeInvalidArgument, "agent_id is required")
	}

	// Get device
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

	// Save updated device
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to deactivate device", err, logger.String("agent_id", agentID))
		return errors.Wrap(err, errors.CodeInternal, "failed to deactivate device")
	}

	s.auditService.LogEvent(ctx, models.AuditEvent{
		EventType: "device.deactivate",
		TenantID:  device.TenantID,
		DeviceID:  agentID,
		Success:   true,
		Details:   fmt.Sprintf("Reason: %s", reason),
	})
	s.logger.Info(ctx, "Device deactivated",
		logger.String("agent_id", agentID),
		logger.String("reason", reason),
	)

	return nil
}

// ListDevicesByTenant lists all devices for a tenant
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

// VerifyDeviceFingerprint verifies if device fingerprint matches
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
func (s *deviceAppServiceImpl) generateDeviceFingerprint(req *dto.RegisterDeviceRequest) string {
	data := fmt.Sprintf("%s:%s",
		req.AgentID,
		req.DeviceType,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// calculateInitialTrustLevel calculates initial trust level based on device information
func (s *deviceAppServiceImpl) calculateInitialTrustLevel(req *dto.RegisterDeviceRequest) constants.TrustLevel {
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
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	token, err := parser.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New(errors.ErrCodeInvalidRequest, "missing kid in token header", "")
		}
		return s.mgrKeyFetcher.GetMgrPublicKey(ctx, clientID, kid)
	})

	if err != nil {
		return errors.Wrap(err, errors.ErrCodeUnauthorized, "invalid client assertion")
	}

	if !token.Valid {
		return errors.New(errors.ErrCodeUnauthorized, "client assertion is not valid", "")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New(errors.ErrCodeUnauthorized, "invalid claims format", "")
	}

	if sub, err := claims.GetSubject(); err != nil || sub != clientID {
		return errors.New(errors.ErrCodeUnauthorized, "invalid subject in client assertion", "")
	}

	if iss, err := claims.GetIssuer(); err != nil || iss != clientID {
		return errors.New(errors.ErrCodeUnauthorized, "invalid issuer in client assertion", "")
	}

	if aud, err := claims.GetAudience(); err != nil || !s.isValidAudience(aud) {
		return errors.New(errors.ErrCodeUnauthorized, "invalid audience in client assertion", "")
	}

	if exp, err := claims.GetExpirationTime(); err != nil || exp.Time.Before(time.Now()) {
		return errors.New(errors.ErrCodeUnauthorized, "client assertion has expired", "")
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

