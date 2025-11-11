package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// DeviceHandler handles HTTP requests related to device management.
// It orchestrates calls to the device application service and formats responses.
// DeviceHandler 处理与设备管理相关的 HTTP 请求。
// 它协调对设备应用服务的调用并格式化响应。
type DeviceHandler struct {
	deviceService service.DeviceAppService
	logger        logger.Logger
}

// NewDeviceHandler creates a new instance of DeviceHandler.
// NewDeviceHandler 创建一个新的 DeviceHandler 实例。
func NewDeviceHandler(
	deviceService service.DeviceAppService,
	log logger.Logger,
) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
		logger:        log,
	}
}

// RegisterDevice handles the endpoint for registering a new device.
// It validates the incoming request and calls the application service to perform the registration.
// POST /api/v1/devices
// RegisterDevice 处理用于注册新设备的端点。
// 它验证传入的请求并调用应用程序服务以执行注册。
func (h *DeviceHandler) RegisterDevice(c *gin.Context) {
	var req dto.DeviceRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Invalid register device request", logger.Error(err))
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	// Validate the request DTO.
	if err := utils.ValidateStruct(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Validation failed for register device request", logger.Error(err))
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	// Call the application service.
	response, err := h.deviceService.RegisterDevice(c.Request.Context(), &req)
	if err != nil {
		h.handleDeviceError(c, err, "register_device")
		return
	}

	h.logger.Info(c.Request.Context(), "Device registered successfully",
		logger.String("tenant_id", req.TenantID),
		logger.String("device_id", response.DeviceID),
	)

	c.JSON(http.StatusCreated, response)
}

// GetDevice handles the endpoint for retrieving information about a specific device.
// GET /api/v1/devices/:device_id
// GetDevice 处理用于检索有关特定设备信息的端点。
func (h *DeviceHandler) GetDevice(c *gin.Context) {
	deviceID := c.Param("device_id")
	if deviceID == "" {
		h.handleDeviceError(c, errors.ErrInvalidRequest("device_id is required"), "get_device")
		return
	}
	resp, err := h.deviceService.GetDeviceInfo(c.Request.Context(), deviceID)
	if err != nil {
		h.handleDeviceError(c, err, "get_device")
		return
	}
	c.JSON(http.StatusOK, resp)
}

// UpdateDevice handles the endpoint for updating a device's information.
// PUT /api/v1/devices/:device_id
// UpdateDevice 处理用于更新设备信息的端点。
func (h *DeviceHandler) UpdateDevice(c *gin.Context) {
	deviceID := c.Param("device_id")
	var req dto.DeviceUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.handleDeviceError(c, errors.ErrInvalidRequest(err.Error()), "update_device")
		return
	}
	req.AgentID = deviceID
	if verr := utils.ValidateStruct(&req); verr != nil {
		h.handleDeviceError(c, errors.ErrInvalidRequest(verr.Error()), "update_device")
		return
	}
	if _, err := h.deviceService.UpdateDeviceInfo(c.Request.Context(), deviceID, &req); err != nil {
		h.handleDeviceError(c, err, "update_device")
		return
	}
	c.AbortWithStatus(http.StatusNoContent)
}

// handleDeviceError provides centralized error handling for device-related operations.
// It logs the error and sends a standardized JSON error response.
// handleDeviceError 为与设备相关的操作提供集中的错误处理。
// 它记录错误并发送标准化的 JSON 错误响应。
func (h *DeviceHandler) handleDeviceError(c *gin.Context, err error, operation string) {
	cbcErr, ok := errors.AsCBCError(err)
	if !ok {
		h.logger.Error(c.Request.Context(), "Unexpected error in device operation", err, logger.String("operation", operation))
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse(err, ""))
		return
	}

	h.logger.Warn(c.Request.Context(), "Device operation failed",
		logger.String("operation", operation),
		logger.String("error_code", string(cbcErr.Code())),
		logger.String("error", cbcErr.Error()))

	c.JSON(cbcErr.HTTPStatus(), dto.ErrorResponse(err, ""))
}
