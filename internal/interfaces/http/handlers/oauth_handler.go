// Package handlers provides HTTP request handlers.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application/service"
)

// OAuthHandler provides handlers for OAuth 2.0 specific endpoints,
// such as the Device Authorization Grant flow (RFC 8628).
// OAuthHandler 为 OAuth 2.0 特定端点提供处理程序，例如设备授权授予流程 (RFC 8628)。
type OAuthHandler struct {
	deviceAuthAppService service.DeviceAuthAppService
}

// NewOAuthHandler creates a new instance of OAuthHandler.
// NewOAuthHandler 创建一个新的 OAuthHandler 实例。
func NewOAuthHandler(deviceAuthAppService service.DeviceAuthAppService) *OAuthHandler {
	return &OAuthHandler{
		deviceAuthAppService: deviceAuthAppService,
	}
}

// DeviceAuthorizationRequest defines the structure for the device authorization request.
// The `form` tags are used by Gin to bind `x-www-form-urlencoded` request bodies.
// DeviceAuthorizationRequest 定义了设备授权请求的结构。
// Gin 使用 `form` 标签来绑定 `x-www-form-urlencoded` 请求体。
type DeviceAuthorizationRequest struct {
	ClientID string `form:"client_id" binding:"required"`
	Scope    string `form:"scope"`
}

// DeviceAuthorizationResponse defines the successful JSON response for the device authorization endpoint.
// DeviceAuthorizationResponse 定义了设备授权端点的成功 JSON 响应。
type DeviceAuthorizationResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// StartDeviceAuthorization is the handler for `POST /oauth/device_authorization`.
// It initiates the device authorization flow by generating and returning device/user codes.
// StartDeviceAuthorization 是 `POST /oauth/device_authorization` 的处理程序。
// 它通过生成并返回设备/用户代码来启动设备授权流程。
func (h *OAuthHandler) StartDeviceAuthorization(c *gin.Context) {
	var req DeviceAuthorizationRequest
	if err := c.ShouldBind(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	resp, err := h.deviceAuthAppService.StartDeviceFlow(c.Request.Context(), req.ClientID, req.Scope)
	if err != nil {
		if e, ok := err.(interface{ Code() string; HTTPStatus() int; Description() string }); ok {
			c.AbortWithStatusJSON(e.HTTPStatus(), gin.H{"error": e.Code(), "error_description": e.Description()})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, DeviceAuthorizationResponse{
		DeviceCode:      resp.DeviceCode,
		UserCode:        resp.UserCode,
		VerificationURI: resp.VerificationURI,
		ExpiresIn:       resp.ExpiresIn,
		Interval:        resp.Interval,
	})
}

// VerifyUserCodeRequest defines the structure for the internal, test-only verification endpoint.
// VerifyUserCodeRequest 定义了仅供内部测试的验证端点的结构。
type VerifyUserCodeRequest struct {
	UserCode string `json:"user_code" binding:"required"`
	Action   string `json:"action" binding:"required,oneof=approve deny"`
	TenantID string `json:"tenant_id"`
	Subject  string `json:"subject"`
}

// VerifyUserCode is a handler for an internal endpoint (`POST /_internal/device_authorization`)
// used for testing and development to simulate the user's approval or denial of a device flow.
// This endpoint would not be exposed in a production environment.
// VerifyUserCode 是一个内部端点 (`POST /_internal/device_authorization`) 的处理程序，
// 用于测试和开发，以模拟用户批准或拒绝设备流。
// 该端点不会在生产环境中公开。
func (h *OAuthHandler) VerifyUserCode(c *gin.Context) {
	var req VerifyUserCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// For an approval action, tenant_id and subject are required to mint the final token.
	if req.Action == "approve" {
		if req.TenantID == "" || req.Subject == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "tenant_id and subject are required for approval"})
			return
		}
	}

	err := h.deviceAuthAppService.VerifyDeviceFlow(c.Request.Context(), req.UserCode, req.Action, req.TenantID, req.Subject)
	if err != nil {
		if e, ok := err.(interface{ Code() string; HTTPStatus() int; Description() string }); ok {
			c.AbortWithStatusJSON(e.HTTPStatus(), gin.H{"error": e.Code(), "error_description": e.Description()})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server_error", "error_description": err.Error()})
		}
		return
	}

	c.Status(http.StatusNoContent)
}
