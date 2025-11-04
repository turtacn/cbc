package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// AuthHandler 认证 HTTP 处理器
type AuthHandler struct {
	authService          service.AuthAppService
	deviceAuthAppService service.DeviceAuthAppService
	metrics              HTTPMetrics
	logger               logger.Logger
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(
	authService service.AuthAppService,
	deviceAuthAppService service.DeviceAuthAppService,
	metrics HTTPMetrics,
	log logger.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService:          authService,
		deviceAuthAppService: deviceAuthAppService,
		metrics:              metrics,
		logger:               log,
	}
}

// IssueToken 签发 Token
// POST /api/v1/auth/token
func (h *AuthHandler) IssueToken(c *gin.Context) {
	h.metrics.RecordRequestStart(c.Request.Context(), "issue_token")
	var req dto.TokenIssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Invalid issue token request", logger.Error(err))
		h.metrics.RecordRequestError(c.Request.Context(), "issue_token", http.StatusBadRequest)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	// 验证请求参数
	if err := utils.ValidateStruct(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Validation failed", logger.Error(err))
		h.metrics.RecordRequestError(c.Request.Context(), "issue_token", http.StatusBadRequest)
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	if req.GrantType == "urn:ietf:params:oauth:grant-type:device_code" {
		response, err := h.deviceAuthAppService.PollDeviceToken(c.Request.Context(), req.DeviceCode, req.ClientID)
		if err != nil {
			h.handleAuthError(c, err, "issue_token")
			return
		}
		c.JSON(http.StatusOK, response)
		return
	}

	// 调用应用服务
	response, err := h.authService.IssueToken(c.Request.Context(), &req)
	if err != nil {
		h.handleAuthError(c, err, "issue_token")
		return
	}

	h.logger.Info(c.Request.Context(), "Token issued successfully",
		logger.String("tenant_id", req.TenantID),
	)

	c.JSON(http.StatusOK, response)
}

// RegisterDevice 注册设备并签发初始 Token
// POST /api/v1/auth/register-device
func (h *AuthHandler) RegisterDevice(c *gin.Context) {
	h.metrics.RecordRequestStart(c.Request.Context(), "register_device")
	var req dto.RegisterDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		bodyBytes, _ := c.GetRawData()
		fmt.Println("Request body:", string(bodyBytes))
		fmt.Println("Binding error:", err)
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
	response, err := h.authService.RegisterDevice(c.Request.Context(), &req)
	if err != nil {
		h.handleAuthError(c, err, "register_device")
		return
	}

	h.logger.Info(c.Request.Context(), "Device registered and token issued successfully",
		logger.String("tenant_id", req.TenantID),
		logger.String("agent_id", req.AgentID),
	)

	c.JSON(http.StatusCreated, response)
}

// RefreshToken 刷新 Token
// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	h.metrics.RecordRequestStart(c.Request.Context(), "refresh_token")

	var req dto.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.handleAuthError(c, errors.ErrInvalidRequest(err.Error()), "refresh_token")
		return
	}
	if verr := utils.ValidateStruct(&req); verr != nil {
		h.handleAuthError(c, errors.ErrInvalidRequest(verr.Error()), "refresh_token")
		return
	}

	resp, err := h.authService.RefreshToken(c.Request.Context(), &req)
	if err != nil {
		h.handleAuthError(c, err, "refresh_token")
		return
	}

	h.metrics.RecordRequestDuration(c.Request.Context(), "refresh_token", http.StatusOK, 0)
	c.JSON(http.StatusOK, resp)
}

// RevokeToken 撤销 Token
// POST /api/v1/auth/revoke
func (h *AuthHandler) RevokeToken(c *gin.Context) {
	h.metrics.RecordRequestStart(c.Request.Context(), "revoke_token")

	var req dto.TokenRevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.handleAuthError(c, errors.ErrInvalidRequest(err.Error()), "revoke_token")
		return
	}
	if verr := utils.ValidateStruct(&req); verr != nil {
		h.handleAuthError(c, errors.ErrInvalidRequest(verr.Error()), "revoke_token")
		return
	}

	if err := h.authService.RevokeToken(c.Request.Context(), &req); err != nil {
		h.handleAuthError(c, err, "revoke_token")
		return
	}

	h.metrics.RecordRequestDuration(c.Request.Context(), "revoke_token", http.StatusNoContent, 0)
	c.AbortWithStatus(http.StatusNoContent)
}

// handleAuthError 统一处理认证错误
func (h *AuthHandler) handleAuthError(c *gin.Context, err error, operation string) {
	cbcErr, ok := errors.AsCBCError(err)
	if !ok {
		h.logger.Error(c.Request.Context(), "Unexpected error in auth operation", err, logger.String("operation", operation))
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse(err, ""))
		return
	}

	h.metrics.RecordRequestError(c.Request.Context(), operation, cbcErr.HTTPStatus())
	h.logger.Warn(c.Request.Context(), "Auth operation failed",
		logger.String("operation", operation),
		logger.String("error_code", string(cbcErr.Code())),
		logger.String("error", cbcErr.Error()))

	c.JSON(cbcErr.HTTPStatus(), dto.ErrorResponse(err, ""))
}
