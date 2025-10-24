// Package service provides application-level services for device management
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// DeviceAppService defines the interface for device application service
type DeviceAppService interface {
	// RegisterDevice registers a new device in the system
	RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.DeviceResponse, error)

	// GetDeviceInfo retrieves device information by agent ID
	GetDeviceInfo(ctx context.Context, agentID string) (*dto.DeviceResponse, error)

	// UpdateDeviceInfo updates device information
	UpdateDeviceInfo(ctx context.Context, agentID string, req *dto.UpdateDeviceRequest) (*dto.DeviceResponse, error)

	// UpdateDeviceTrustLevel updates device trust level
	UpdateDeviceTrustLevel(ctx context.Context, agentID string, trustLevel models.TrustLevel) error

	// DeactivateDevice deactivates a device
	DeactivateDevice(ctx context.Context, agentID string, reason string) error

	// ListDevicesByTenant lists all devices for a tenant
	ListDevicesByTenant(ctx context.Context, tenantID string, page, pageSize int) ([]*dto.DeviceResponse, int64, error)

	// VerifyDeviceFingerprint verifies if device fingerprint matches
	VerifyDeviceFingerprint(ctx context.Context, agentID, fingerprint string) (bool, error)
}

// deviceAppServiceImpl is the concrete implementation of DeviceAppService
type deviceAppServiceImpl struct {
	deviceRepo repository.DeviceRepository
	logger     logger.Logger
}

// NewDeviceAppService creates a new instance of DeviceAppService
func NewDeviceAppService(
	deviceRepo repository.DeviceRepository,
	log logger.Logger,
) DeviceAppService {
	return &deviceAppServiceImpl{
		deviceRepo: deviceRepo,
		logger:     log,
	}
}

// RegisterDevice implements device registration
func (s *deviceAppServiceImpl) RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.DeviceResponse, error) {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid register device request", "error", err)
		return nil, errors.ErrInvalidRequest.Wrap(err)
	}

	// Check if device already exists
	existingDevice, err := s.deviceRepo.GetByAgentID(ctx, req.AgentID)
	if err != nil && !errors.IsNotFoundError(err) {
		s.logger.Error(ctx, "Failed to check device existence", "agent_id", req.AgentID, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}

	if existingDevice != nil {
		s.logger.Warn(ctx, "Device already exists", "agent_id", req.AgentID)
		return nil, errors.ErrDeviceAlreadyExists
	}

	// Generate device fingerprint hash if not provided
	deviceFingerprint := req.DeviceFingerprint
	if deviceFingerprint == "" {
		deviceFingerprint = s.generateDeviceFingerprint(req)
	}

	// Create device model
	device := &models.Device{
		AgentID:           req.AgentID,
		TenantID:          req.TenantID,
		DeviceFingerprint: deviceFingerprint,
		DeviceName:        req.DeviceName,
		DeviceType:        req.DeviceType,
		TrustLevel:        s.calculateInitialTrustLevel(req),
		Status:            models.DeviceStatusActive,
		RegisteredAt:      time.Now(),
		LastSeenAt:        time.Now(),
		IPAddress:         req.IPAddress,
		UserAgent:         req.UserAgent,
		Metadata:          req.Metadata,
	}

	// Save device to database
	if err := s.deviceRepo.Create(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to create device", "agent_id", req.AgentID, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}

	// Record audit log
	s.logger.Info(ctx, "Device registered successfully",
		"agent_id", req.AgentID,
		"tenant_id", req.TenantID,
		"device_type", req.DeviceType,
		"trust_level", device.TrustLevel,
	)

	return s.deviceToResponse(device), nil
}

// GetDeviceInfo retrieves device information
func (s *deviceAppServiceImpl) GetDeviceInfo(ctx context.Context, agentID string) (*dto.DeviceResponse, error) {
	if agentID == "" {
		return nil, errors.ErrInvalidRequest.WithMessage("agent_id is required")
	}

	device, err := s.deviceRepo.GetByAgentID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			s.logger.Warn(ctx, "Device not found", "agent_id", agentID)
			return nil, errors.ErrDeviceNotFound
		}
		s.logger.Error(ctx, "Failed to get device", "agent_id", agentID, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}

	return s.deviceToResponse(device), nil
}

// UpdateDeviceInfo updates device information
func (s *deviceAppServiceImpl) UpdateDeviceInfo(ctx context.Context, agentID string, req *dto.UpdateDeviceRequest) (*dto.DeviceResponse, error) {
	// Validate request
	if err := utils.ValidateStruct(req); err != nil {
		s.logger.Error(ctx, "Invalid update device request", "error", err)
		return nil, errors.ErrInvalidRequest.Wrap(err)
	}

	// Get existing device
	device, err := s.deviceRepo.GetByAgentID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			s.logger.Warn(ctx, "Device not found", "agent_id", agentID)
			return nil, errors.ErrDeviceNotFound
		}
		s.logger.Error(ctx, "Failed to get device", "agent_id", agentID, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}

	// Update fields if provided
	if req.DeviceName != "" {
		device.DeviceName = req.DeviceName
	}
	if req.DeviceType != "" {
		device.DeviceType = req.DeviceType
	}
	if req.IPAddress != "" {
		device.IPAddress = req.IPAddress
	}
	if req.UserAgent != "" {
		device.UserAgent = req.UserAgent
	}
	if req.Metadata != nil {
		device.Metadata = req.Metadata
	}

	device.LastSeenAt = time.Now()

	// Save updated device
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to update device", "agent_id", agentID, "error", err)
		return nil, errors.ErrInternalServer.Wrap(err)
	}

	s.logger.Info(ctx, "Device updated successfully", "agent_id", agentID)

	return s.deviceToResponse(device), nil
}

// UpdateDeviceTrustLevel updates device trust level
func (s *deviceAppServiceImpl) UpdateDeviceTrustLevel(ctx context.Context, agentID string, trustLevel models.TrustLevel) error {
	if agentID == "" {
		return errors.ErrInvalidRequest.WithMessage("agent_id is required")
	}

	// Validate trust level
	switch trustLevel {
	case models.TrustLevelHigh, models.TrustLevelMedium, models.TrustLevelLow, models.TrustLevelUntrusted:
		// Valid trust level
	default:
		return errors.ErrInvalidRequest.WithMessage("invalid trust level")
	}

	// Get device
	device, err := s.deviceRepo.GetByAgentID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return errors.ErrDeviceNotFound
		}
		s.logger.Error(ctx, "Failed to get device", "agent_id", agentID, "error", err)
		return errors.ErrInternalServer.Wrap(err)
	}

	oldTrustLevel := device.TrustLevel
	device.TrustLevel = trustLevel

	// Save updated device
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to update device trust level", "agent_id", agentID, "error", err)
		return errors.ErrInternalServer.Wrap(err)
	}

	s.logger.Info(ctx, "Device trust level updated",
		"agent_id", agentID,
		"old_trust_level", oldTrustLevel,
		"new_trust_level", trustLevel,
	)

	return nil
}

// DeactivateDevice deactivates a device
func (s *deviceAppServiceImpl) DeactivateDevice(ctx context.Context, agentID string, reason string) error {
	if agentID == "" {
		return errors.ErrInvalidRequest.WithMessage("agent_id is required")
	}

	// Get device
	device, err := s.deviceRepo.GetByAgentID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return errors.ErrDeviceNotFound
		}
		s.logger.Error(ctx, "Failed to get device", "agent_id", agentID, "error", err)
		return errors.ErrInternalServer.Wrap(err)
	}

	if device.Status == models.DeviceStatusInactive {
		s.logger.Warn(ctx, "Device already inactive", "agent_id", agentID)
		return nil
	}

	device.Status = models.DeviceStatusInactive

	// Save updated device
	if err := s.deviceRepo.Update(ctx, device); err != nil {
		s.logger.Error(ctx, "Failed to deactivate device", "agent_id", agentID, "error", err)
		return errors.ErrInternalServer.Wrap(err)
	}

	s.logger.Info(ctx, "Device deactivated",
		"agent_id", agentID,
		"reason", reason,
	)

	return nil
}

// ListDevicesByTenant lists all devices for a tenant
func (s *deviceAppServiceImpl) ListDevicesByTenant(ctx context.Context, tenantID string, page, pageSize int) ([]*dto.DeviceResponse, int64, error) {
	if tenantID == "" {
		return nil, 0, errors.ErrInvalidRequest.WithMessage("tenant_id is required")
	}

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	devices, total, err := s.deviceRepo.ListByTenant(ctx, tenantID, page, pageSize)
	if err != nil {
		s.logger.Error(ctx, "Failed to list devices", "tenant_id", tenantID, "error", err)
		return nil, 0, errors.ErrInternalServer.Wrap(err)
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
		return false, errors.ErrInvalidRequest.WithMessage("agent_id and fingerprint are required")
	}

	device, err := s.deviceRepo.GetByAgentID(ctx, agentID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, errors.ErrDeviceNotFound
		}
		s.logger.Error(ctx, "Failed to get device", "agent_id", agentID, "error", err)
		return false, errors.ErrInternalServer.Wrap(err)
	}

	matches := device.DeviceFingerprint == fingerprint

	if !matches {
		s.logger.Warn(ctx, "Device fingerprint mismatch",
			"agent_id", agentID,
			"expected", device.DeviceFingerprint,
			"provided", fingerprint,
		)
	}

	return matches, nil
}

// generateDeviceFingerprint generates a device fingerprint hash
func (s *deviceAppServiceImpl) generateDeviceFingerprint(req *dto.RegisterDeviceRequest) string {
	data := fmt.Sprintf("%s:%s:%s:%s",
		req.AgentID,
		req.DeviceType,
		req.UserAgent,
		req.IPAddress,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// calculateInitialTrustLevel calculates initial trust level based on device information
func (s *deviceAppServiceImpl) calculateInitialTrustLevel(req *dto.RegisterDeviceRequest) models.TrustLevel {
	// Default trust level is medium
	trustLevel := models.TrustLevelMedium

	// If device has strong fingerprint (e.g., TPM/TEE binding), set high trust
	// This is a simplified logic, real implementation would check actual hardware features
	if req.DeviceFingerprint != "" && len(req.DeviceFingerprint) >= 64 {
		trustLevel = models.TrustLevelHigh
	}

	// If device metadata indicates weak security, lower trust level
	if metadata, ok := req.Metadata["security_features"]; ok {
		if securityFeatures, ok := metadata.(map[string]interface{}); ok {
			if hasTPM, ok := securityFeatures["has_tpm"].(bool); ok && hasTPM {
				trustLevel = models.TrustLevelHigh
			}
		}
	}

	return trustLevel
}

// deviceToResponse converts device model to response DTO
func (s *deviceAppServiceImpl) deviceToResponse(device *models.Device) *dto.DeviceResponse {
	return &dto.DeviceResponse{
		AgentID:           device.AgentID,
		TenantID:          device.TenantID,
		DeviceFingerprint: device.DeviceFingerprint,
		DeviceName:        device.DeviceName,
		DeviceType:        device.DeviceType,
		TrustLevel:        string(device.TrustLevel),
		Status:            string(device.Status),
		RegisteredAt:      device.RegisteredAt,
		LastSeenAt:        device.LastSeenAt,
		IPAddress:         device.IPAddress,
		UserAgent:         device.UserAgent,
		Metadata:          device.Metadata,
	}
}

//Personal.AI order the ending

