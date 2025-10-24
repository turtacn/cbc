package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/pkg/errors"
)

// DeviceHandler handles HTTP requests for device management.
type DeviceHandler struct {
	deviceService service.DeviceAppService
}

// NewDeviceHandler creates a new DeviceHandler.
func NewDeviceHandler(deviceService service.DeviceAppService) *DeviceHandler {
	return &DeviceHandler{deviceService: deviceService}
}

// RegisterDevice handles the request to register a new device.
func (h *DeviceHandler) RegisterDevice(c *gin.Context) {
	var req dto.DeviceRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		dto.SendError(c, errors.ErrInvalidRequest.WithError(err))
		return
	}

	device, err := h.deviceService.RegisterDevice(c.Request.Context(), &req)
	if err != nil {
		dto.SendError(c, err)
		return
	}

	dto.SendSuccess(c, http.StatusCreated, device)
}

// GetDevice handles the request to get device information.
func (h *DeviceHandler) GetDevice(c *gin.Context) {
	deviceIDStr := c.Param("device_id")
	deviceID, parseErr := uuid.Parse(deviceIDStr)
	if parseErr != nil {
		dto.SendError(c, errors.ErrInvalidRequest.WithError(parseErr))
		return
	}

	// In a real implementation, tenantID would come from the auth context.
	tenantID := uuid.New()
	device, err := h.deviceService.GetDeviceInfo(c.Request.Context(), tenantID, deviceID)
	if err != nil {
		dto.SendError(c, err)
		return
	}

	dto.SendSuccess(c, http.StatusOK, device)
}

// UpdateDevice handles the request to update device information.
func (h *DeviceHandler) UpdateDevice(c *gin.Context) {
	deviceIDStr := c.Param("device_id")
	deviceID, parseErr := uuid.Parse(deviceIDStr)
	if parseErr != nil {
		dto.SendError(c, errors.ErrInvalidRequest.WithError(parseErr))
		return
	}

	var req dto.DeviceUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		dto.SendError(c, errors.ErrInvalidRequest.WithError(err))
		return
	}

	tenantID := uuid.New()
	device, err := h.deviceService.UpdateDeviceInfo(c.Request.Context(), tenantID, deviceID, &req)
	if err != nil {
		dto.SendError(c, err)
		return
	}

	dto.SendSuccess(c, http.StatusOK, device)
}
//Personal.AI order the ending