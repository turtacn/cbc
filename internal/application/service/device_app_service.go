package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// DeviceAppService defines the interface for device-related application services.
type DeviceAppService interface {
	RegisterDevice(ctx context.Context, req *dto.DeviceRegisterRequest) (*dto.DeviceResponse, *errors.AppError)
	GetDeviceInfo(ctx context.Context, tenantID, deviceID uuid.UUID) (*dto.DeviceResponse, *errors.AppError)
	UpdateDeviceInfo(ctx context.Context, tenantID, deviceID uuid.UUID, req *dto.DeviceUpdateRequest) (*dto.DeviceResponse, *errors.AppError)
}

type deviceAppServiceImpl struct {
	deviceRepo repository.DeviceRepository
	log        logger.Logger
}

// NewDeviceAppService creates a new DeviceAppService.
func NewDeviceAppService(deviceRepo repository.DeviceRepository, log logger.Logger) DeviceAppService {
	return &deviceAppServiceImpl{
		deviceRepo: deviceRepo,
		log:        log,
	}
}

// RegisterDevice handles the registration of a new device.
func (s *deviceAppServiceImpl) RegisterDevice(ctx context.Context, req *dto.DeviceRegisterRequest) (*dto.DeviceResponse, *errors.AppError) {
	if err := utils.ValidateStruct(req); err != nil {
		return nil, err
	}

	device := models.NewDevice(req.DeviceID, req.TenantID, req.DeviceType, req.OS, req.AppVersion)

	if err := s.deviceRepo.Save(ctx, device); err != nil {
		return nil, err
	}

	s.log.Info(ctx, "Device registered successfully", logger.Fields{"device_id": device.DeviceID, "tenant_id": device.TenantID})
	return utils.DeviceToDTO(device), nil
}

// GetDeviceInfo retrieves information about a specific device.
func (s *deviceAppServiceImpl) GetDeviceInfo(ctx context.Context, tenantID, deviceID uuid.UUID) (*dto.DeviceResponse, *errors.AppError) {
	// A real implementation would find by tenantID and the string deviceID
	device, err := s.deviceRepo.FindByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	return utils.DeviceToDTO(device), nil
}

// UpdateDeviceInfo updates a device's information.
func (s *deviceAppServiceImpl) UpdateDeviceInfo(ctx context.Context, tenantID, deviceID uuid.UUID, req *dto.DeviceUpdateRequest) (*dto.DeviceResponse, *errors.AppError) {
	device, err := s.deviceRepo.FindByID(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	if req.DeviceName != nil {
		device.DeviceName = *req.DeviceName
	}
	if req.AppVersion != nil {
		device.AppVersion = *req.AppVersion
	}

	if err := s.deviceRepo.Save(ctx, device); err != nil {
		return nil, err
	}

	s.log.Info(ctx, "Device updated successfully", logger.Fields{"device_id": device.DeviceID})
	return utils.DeviceToDTO(device), nil
}

//Personal.AI order the ending
