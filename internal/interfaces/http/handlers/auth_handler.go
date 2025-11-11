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

// AuthHandler handles HTTP requests related to authentication, such as token issuance, refresh, and revocation.
// It acts as the presentation layer, translating HTTP requests into application service calls.
// AuthHandler 处理与身份验证相关的 HTTP 请求，例如令牌颁发、刷新和撤销。
// 它充当表示层，将 HTTP 请求转换为应用程序服务调用。
type AuthHandler struct {
	authService          service.AuthAppService
	deviceAuthAppService service.DeviceAuthAppService
	logger               logger.Logger
}

// NewAuthHandler creates a new instance of AuthHandler with its required dependencies.
// NewAuthHandler 使用其所需的依赖项创建一个新的 AuthHandler 实例。
func NewAuthHandler(
	authService service.AuthAppService,
	deviceAuthAppService service.DeviceAuthAppService,
	log logger.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService:          authService,
		deviceAuthAppService: deviceAuthAppService,
		logger:               log,
	}
}

// IssueToken handles the endpoint for issuing access and refresh tokens.
// It supports various grant types, including the device code grant.
// POST /api/v1/auth/token
// IssueToken 处理用于颁发访问和刷新令牌的端点。
// 它支持各种授权类型，包括设备代码授权。
func (h *AuthHandler) IssueToken(c *gin.Context) {
	var req dto.TokenIssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Invalid issue token request", logger.Error(err))
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	// Validate the request DTO.
	if err := utils.ValidateStruct(&req); err != nil {
		h.logger.Warn(c.Request.Context(), "Validation failed for issue token request", logger.Error(err))
		c.JSON(http.StatusBadRequest, dto.ErrorResponse(err, ""))
		return
	}

	// Special handling for the device code grant type.
	if req.GrantType == "urn:ietf:params:oauth:grant-type:device_code" {
		response, err := h.deviceAuthAppService.PollDeviceToken(c.Request.Context(), req.DeviceCode, req.ClientID)
		if err != nil {
			h.handleAuthError(c, err, "issue_token_device_code")
			return
		}
		c.JSON(http.StatusOK, response)
		return
	}

	// Call the main authentication service for other grant types.
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

// RegisterDevice handles the endpoint for registering a new device and issuing its initial token.
// POST /api/v1/auth/register-device
// RegisterDevice 处理用于注册新设备并颁发其初始令牌的端点。
func (h *AuthHandler) RegisterDevice(c *gin.Context) {
	var req dto.RegisterDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		bodyBytes, _ := c.GetRawData()
		fmt.Println("Request body:", string(bodyBytes))
		fmt.Println("Binding error:", err)
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

	// Call the application service to perform device registration.
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

// RefreshToken handles the endpoint for refreshing an access token using a refresh token.
// POST /api/v1/auth/refresh
// RefreshToken 处理用于使用刷新令牌刷新访问令牌的端点。
func (h *AuthHandler) RefreshToken(c *gin.Context) {
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

	c.JSON(http.StatusOK, resp)
}

// RevokeToken handles the endpoint for revoking a refresh or access token.
// POST /api/v1/auth/revoke
// RevokeToken 处理用于撤销刷新或访问令牌的端点。
func (h *AuthHandler) RevokeToken(c *gin.Context) {
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

	c.AbortWithStatus(http.StatusNoContent)
}

// handleAuthError provides centralized error handling for the authentication endpoints.
// It logs the error and sends a standardized JSON error response.
// handleAuthError 为身份验证端点提供集中的错误处理。
// 它记录错误并发送标准化的 JSON 错误响应。
func (h *AuthHandler) handleAuthError(c *gin.Context, err error, operation string) {
	cbcErr, ok := errors.AsCBCError(err)
	if !ok {
		// This is an unexpected, non-domain error.
		h.logger.Error(c.Request.Context(), "Unexpected error in auth operation", err, logger.String("operation", operation))
		c.JSON(http.StatusInternalServerError, dto.ErrorResponse(err, ""))
		return
	}

	h.logger.Warn(c.Request.Context(), "Auth operation failed",
		logger.String("operation", operation),
		logger.String("error_code", string(cbcErr.Code())),
		logger.String("error", cbcErr.Error()))

	// Respond with the appropriate HTTP status and error details.
	c.JSON(cbcErr.HTTPStatus(), dto.ErrorResponse(err, ""))
}
