package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// AuthHandler 认证 HTTP 处理器
type AuthHandler struct {
	authService service.AuthAppService
	metrics     *monitoring.Metrics
	logger      logger.Logger
	validator   *utils.Validator
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(
	authService service.AuthAppService,
	metrics *monitoring.Metrics,
	log logger.Logger,
	validator *utils.Validator,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		metrics:     metrics,
		logger:      log,
		validator:   validator,
	}
}

// IssueToken 签发 Token
// POST /api/v1/auth/token
func (h *AuthHandler) IssueToken(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("auth", "issue_token")
	defer h.metrics.RecordRequestDuration("auth", "issue_token", startTime)

	var req dto.IssueTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid issue token request", "error", err)
		h.metrics.RecordRequestError("auth", "issue_token", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body: " + err.Error(),
		})
		return
	}

	// 验证请求参数
	if err := h.validator.ValidateStruct(&req); err != nil {
		h.logger.Warn("Validation failed", "error", err)
		h.metrics.RecordRequestError("auth", "issue_token", "validation_failed")
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
	response, err := h.authService.IssueToken(c.Request.Context(), &req)
	if err != nil {
		h.handleAuthError(c, err, "issue_token")
		return
	}

	h.metrics.RecordRequestSuccess("auth", "issue_token")
	h.logger.Info("Token issued successfully",
		"tenant_id", req.TenantID,
		"device_id", req.DeviceID,
		"trace_id", req.TraceID)

	c.JSON(http.StatusOK, response)
}

// RefreshToken 刷新 Token
// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("auth", "refresh_token")
	defer h.metrics.RecordRequestDuration("auth", "refresh_token", startTime)

	var req dto.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid refresh token request", "error", err)
		h.metrics.RecordRequestError("auth", "refresh_token", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body: " + err.Error(),
		})
		return
	}

	// 验证请求参数
	if err := h.validator.ValidateStruct(&req); err != nil {
		h.logger.Warn("Validation failed", "error", err)
		h.metrics.RecordRequestError("auth", "refresh_token", "validation_failed")
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
	response, err := h.authService.RefreshToken(c.Request.Context(), &req)
	if err != nil {
		h.handleAuthError(c, err, "refresh_token")
		return
	}

	h.metrics.RecordRequestSuccess("auth", "refresh_token")
	h.logger.Info("Token refreshed successfully",
		"trace_id", req.TraceID)

	c.JSON(http.StatusOK, response)
}

// RevokeToken 撤销 Token
// POST /api/v1/auth/revoke
func (h *AuthHandler) RevokeToken(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("auth", "revoke_token")
	defer h.metrics.RecordRequestDuration("auth", "revoke_token", startTime)

	var req dto.RevokeTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Invalid revoke token request", "error", err)
		h.metrics.RecordRequestError("auth", "revoke_token", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid request body: " + err.Error(),
		})
		return
	}

	// 验证请求参数
	if err := h.validator.ValidateStruct(&req); err != nil {
		h.logger.Warn("Validation failed", "error", err)
		h.metrics.RecordRequestError("auth", "revoke_token", "validation_failed")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: err.Error(),
		})
		return
	}

	// 提取请求元数据
	req.OperatorID = c.GetString("operator_id") // 从认证上下文获取
	req.TraceID = c.GetString("trace_id")

	// 调用应用服务
	err := h.authService.RevokeToken(c.Request.Context(), &req)
	if err != nil {
		h.handleAuthError(c, err, "revoke_token")
		return
	}

	h.metrics.RecordRequestSuccess("auth", "revoke_token")
	h.logger.Info("Token revoked successfully",
		"jti", req.JTI,
		"operator_id", req.OperatorID,
		"trace_id", req.TraceID)

	c.JSON(http.StatusOK, dto.SuccessResponse{
		Success: true,
		Message: "Token revoked successfully",
	})
}

// GetPublicKeys 获取租户的公钥集 (JWKS 格式)
// GET /api/v1/auth/jwks/:tenant_id
func (h *AuthHandler) GetPublicKeys(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("auth", "get_public_keys")
	defer h.metrics.RecordRequestDuration("auth", "get_public_keys", startTime)

	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		h.logger.Warn("Missing tenant_id parameter")
		h.metrics.RecordRequestError("auth", "get_public_keys", "invalid_request")
		c.JSON(http.StatusBadRequest, dto.ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Missing tenant_id parameter",
		})
		return
	}

	// 调用应用服务
	jwks, err := h.authService.GetPublicKeys(c.Request.Context(), tenantID)
	if err != nil {
		h.handleAuthError(c, err, "get_public_keys")
		return
	}

	h.metrics.RecordRequestSuccess("auth", "get_public_keys")
	c.JSON(http.StatusOK, jwks)
}

// IntrospectToken 内省 Token (验证 Token 有效性并返回 Claims)
// POST /api/v1/auth/introspect
func (h *AuthHandler) IntrospectToken(c *gin.Context) {
	startTime := h.metrics.RecordRequestStart("auth", "introspect_token")
	defer h.metrics.RecordRequestDuration("auth", "introspect_token", startTime)

	// 从 Authorization Header 提取 Token
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		h.logger.Warn("Missing Authorization header")
		h.metrics.RecordRequestError("auth", "introspect_token", "missing_token")
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "Missing Authorization header",
		})
		return
	}

	// 提取 Bearer Token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		h.logger.Warn("Invalid Authorization header format")
		h.metrics.RecordRequestError("auth", "introspect_token", "invalid_token")
		c.JSON(http.StatusUnauthorized, dto.ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "Invalid Authorization header format",
		})
		return
	}

	token := parts[1]

	// 调用应用服务
	introspection, err := h.authService.IntrospectToken(c.Request.Context(), token)
	if err != nil {
		h.handleAuthError(c, err, "introspect_token")
		return
	}

	h.metrics.RecordRequestSuccess("auth", "introspect_token")
	c.JSON(http.StatusOK, introspection)
}

// handleAuthError 统一处理认证错误
func (h *AuthHandler) handleAuthError(c *gin.Context, err error, operation string) {
	h.metrics.RecordRequestError("auth", operation, err.Error())

	var appErr *errors.AppError
	if errors.As(err, &appErr) {
		h.logger.Warn("Auth operation failed",
			"operation", operation,
			"error_code", appErr.Code,
			"error", appErr.Message)

		statusCode := http.StatusInternalServerError
		switch appErr.Code {
		case errors.ErrCodeInvalidRequest, errors.ErrCodeValidationFailed:
			statusCode = http.StatusBadRequest
		case errors.ErrCodeUnauthorized, errors.ErrCodeInvalidToken:
			statusCode = http.StatusUnauthorized
		case errors.ErrCodeForbidden:
			statusCode = http.StatusForbidden
		case errors.ErrCodeNotFound:
			statusCode = http.StatusNotFound
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
	h.logger.Error("Unexpected error in auth operation",
		"operation", operation,
		"error", err)

	c.JSON(http.StatusInternalServerError, dto.ErrorResponse{
		Error:            "internal_server_error",
		ErrorDescription: "An unexpected error occurred",
	})
}

//Personal.AI order the ending
