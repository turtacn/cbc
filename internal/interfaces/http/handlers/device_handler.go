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

// DeviceHandler 设备 HTTP 处理器
type DeviceHandler struct {
	deviceService service.DeviceAppService
	metrics       HTTPMetrics
	logger        logger.Logger
}

// NewDeviceHandler 创建设备处理器
func NewDeviceHandler(
	deviceService service.DeviceAppService,
	metrics HTTPMetrics,
	log logger.Logger,
) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
		metrics:       metrics,
		logger:        log,
	}
}

// RegisterDevice 注册设备
// POST /api/v1/devices
func (h *DeviceHandler) RegisterDevice(c *gin.Context) {
	h.metrics.RecordRequestStart(c.Request.Context(), "register_device")
	var req dto.DeviceRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Invalid register device request", logger.Error(err))
		h.metrics.RecordRequestError(c.Request.Context(), "register_device", http.StatusBadRequest)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	// 验证请求参数
	if err := utils.ValidateStruct(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Validation failed", logger.Error(err))
		h.metrics.RecordRequestError(c.Request.Context(), "register_device", http.StatusBadRequest)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	// 调用应用服务
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

// GetDevice 获取设备信息
// GET /api/v1/devices/:device_id
func (h *DeviceHandler) GetDevice(c *gin.Context) {
	deviceID := c.Param("device_id")
	if deviceID == "" {
		h.handleDeviceError(c, errors.ErrInvalidRequest("device_id required"), "get_device")
		return
	}
	resp, err := h.deviceService.GetDeviceInfo(c.Request.Context(), deviceID)
	if err != nil {
		h.handleDeviceError(c, err, "get_device")
		return
	}
	c.JSON(http.StatusOK, resp)
}

// UpdateDevice 更新设备信息
// PUT /i/v1/devices/:device_id
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

// handleDeviceError 统一处理设备错误
func (h *DeviceHandler) handleDeviceError(c *gin.Context, err error, operation string) {
	cbcErr, ok := errors.AsCBCError(err)
	if !ok {
		h.logger.Error(c.Request.Context(), "Unexpected error in device operation", err, logger.String("operation", operation))
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse(err, ""))
		return
	}

	h.metrics.RecordRequestError(c.Request.Context(), operation, cbcErr.HTTPStatus())
	h.logger.Warn(c.Request.Context(), "Device operation failed",
		logger.String("operation", operation),
		logger.String("error_code", string(cbcErr.Code())),
		logger.String("error", cbcErr.Error()))

	c.JSON(cbcErr.HTTPStatus(), dto.ErrorResponse(err, ""))
}
