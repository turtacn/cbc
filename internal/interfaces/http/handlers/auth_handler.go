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

// AuthHandler 认证 HTTP 处理器
type AuthHandler struct {
	authService service.AuthAppService
	metrics     HTTPMetrics
	logger      logger.Logger
}

// NewAuthHandler 创建认证处理器
func NewAuthHandler(
	authService service.AuthAppService,
	metrics HTTPMetrics,
	log logger.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		metrics:     metrics,
		logger:      log,
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
