package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// DeviceHandler 设备 HTTP 处理器
type DeviceHandler struct {
	deviceService service.DeviceAppService
	metrics       *monitoring.Metrics
	logger        logger.Logger
	validator     *utils.Validator
}

// NewDeviceHandler 创建设备处理器
func NewDeviceHandler(
	deviceService service.DeviceAppService,
	metrics *monitoring.Metrics,
	log logger.Logger,
	validator *utils.Validator,
) *DeviceHandler {
	return &DeviceHandler{
		deviceService: deviceService,
		metrics:       metrics,
		logger:        log,
		validator:     validator,
	}
}

// RegisterDevice 注册设备
// POST /api/v1/devices
func (h *DeviceHandler) RegisterDevice(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("device", "register")
	defer h.metrics.RecordRequestDuration("device", "register", startTime)

	var req dto.RegisterDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid register device request", "error", err)
		h.metrics.RecordRequestError("device", "register", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body: " + err.Error(),
		})
		return
	}

	// 验证请求参数
	if err := h.validator.ValidateStruct(&req); err != nil {
		h.logger.Warn("Validation failed", "error", err)
		h.metrics.RecordRequestError("device", "register", "validation_failed")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	// 提取请求元数据
	req.IPAddress = c.ClientIP()
	req.UserAgent = c.GetHeader("User-Agent")
	req.TraceID = c.GetString("trace_id")

	// 调用应用服务
	response, err := h.deviceService.RegisterDevice(c.Request.Context(), &req)
	if err != nil {
		h.handleDeviceError(c, err, "register")
		return
	}

	h.metrics.RecordRequestSuccess("device", "register")
	h.logger.Info("Device registered successfully",
		"tenant_id", req.TenantID,
		"device_id", response.DeviceID,
		"trace_id", req.TraceID)

	c.JSON(http.StatusCreated, response)
}

// GetDeviceInfo 获取设备信息
// GET /api/v1/devices/:device_id
func (h *DeviceHandler) GetDeviceInfo(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("device", "get_info")
	defer h.metrics.RecordRequestDuration("device", "get_info", startTime)

	deviceID := c.Param("device_id")
	if deviceID == "" {
		h.logger.Warn("Missing device_id parameter")
		h.metrics.RecordRequestError("device", "get_info", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Missing device_id parameter",
		})
		return
	}

	tenantID := c.GetString("tenant_id") // 从认证上下文获取
	if tenantID == "" {
		h.logger.Warn("Missing tenant_id in context")
		h.metrics.RecordRequestError("device", "get_info", "unauthorized")
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Missing tenant_id in context",
		})
		return
	}

	// 调用应用服务
	deviceInfo, err := h.deviceService.GetDeviceInfo(c.Request.Context(), tenantID, deviceID)
	if err != nil {
		h.handleDeviceError(c, err, "get_info")
		return
	}

	h.metrics.RecordRequestSuccess("device", "get_info")
	c.JSON(http.StatusOK, deviceInfo)
}

// UpdateDeviceInfo 更新设备信息
// PUT /api/v1/devices/:device_id
func (h *DeviceHandler) UpdateDeviceInfo(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("device", "update")
	defer h.metrics.RecordRequestDuration("device", "update", startTime)

	deviceID := c.Param("device_id")
	if deviceID == "" {
		h.logger.Warn("Missing device_id parameter")
		h.metrics.RecordRequestError("device", "update", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Missing device_id parameter",
		})
		return
	}

	var req dto.UpdateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid update device request", "error", err)
		h.metrics.RecordRequestError("device", "update", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body: " + err.Error(),
		})
		return
	}

	// 验证请求参数
	if err := h.validator.ValidateStruct(&req); err != nil {
		h.logger.Warn("Validation failed", "error", err)
		h.metrics.RecordRequestError("device", "update", "validation_failed")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	req.DeviceID = deviceID
	req.TenantID = c.GetString("tenant_id") // 从认证上下文获取
	req.TraceID = c.GetString("trace_id")

	// 调用应用服务
	err := h.deviceService.UpdateDeviceInfo(c.Request.Context(), &req)
	if err != nil {
		h.handleDeviceError(c, err, "update")
		return
	}

	h.metrics.RecordRequestSuccess("device", "update")
	h.logger.Info("Device updated successfully",
		"tenant_id", req.TenantID,
		"device_id", req.DeviceID,
		"trace_id", req.TraceID)

	c.JSON(http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Device updated successfully",
	})
}

// ListDevices 列出设备
// GET /api/v1/devices
func (h *DeviceHandler) ListDevices(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("device", "list")
	defer h.metrics.RecordRequestDuration("device", "list", startTime)

	tenantID := c.GetString("tenant_id") // 从认证上下文获取
	if tenantID == "" {
		h.logger.Warn("Missing tenant_id in context")
		h.metrics.RecordRequestError("device", "list", "unauthorized")
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Error:            "unauthorized",
			ErrorDescription: "Missing tenant_id in context",
		})
		return
	}

	// 解析分页参数
	var req dto.ListDevicesRequest
	req.TenantID = tenantID
	req.Page = utils.ParseIntQueryParam(c, "page", 1)
	req.PageSize = utils.ParseIntQueryParam(c, "page_size", 20)
	req.Status = c.Query("status")

	// 调用应用服务
	devices, total, err := h.deviceService.ListDevices(c.Request.Context(), &req)
	if err != nil {
		h.handleDeviceError(c, err, "list")
		return
	}

	h.metrics.RecordRequestSuccess("device", "list")
	c.JSON(http.StatusOK, dto.ListDevicesResponse{
		Devices:  devices,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	})
}

// handleDeviceError 统一处理设备错误
func (h *DeviceHandler) handleDeviceError(c *gin.Context, err error, operation string) {
	h.metrics.RecordRequestError("device", operation, err.Error())

	var appErr *errors.AppError
	if errors.As(err, &appErr) {
		h.logger.Warn("Device operation failed",
			"operation", operation,
			"error_code", appErr.Code,
			"error", appErr.Message)

		statusCode := http.StatusInternalServerError
		switch appErr.Code {
		case errors.ErrCodeInvalidRequest, errors.ErrCodeValidationFailed:
			statusCode = http.StatusBadRequest
		case errors.ErrCodeUnauthorized:
			statusCode = http.StatusUnauthorized
		case errors.ErrCodeForbidden:
			statusCode = http.StatusForbidden
		case errors.ErrCodeNotFound:
			statusCode = http.StatusNotFound
		case errors.ErrCodeConflict:
			statusCode = http.StatusConflict
		case errors.ErrCodeRateLimitExceeded:
			statusCode = http.StatusTooManyRequests
		}

		c.JSON(statusCode, dto.ErrorResponse{
			Error:            appErr.Code,
			ErrorDescription: appErr.Message,
			ErrorURI:         appErr.URI,
		})
		return
	}

	// 未知错误
	h.logger.Error("Unexpected error in device operation",
		"operation", operation,
		"error", err)

	c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
		Error:            "internal_server_error",
		ErrorDescription: "An unexpected error occurred",
	})
}

//Personal.AI order the ending
