// Package handlers provides HTTP request handlers.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application/service"
)

// OAuthHandler handles OAuth 2.0 specific endpoints like device authorization.
type OAuthHandler struct {
	deviceAuthAppService service.DeviceAuthAppService
}

// NewOAuthHandler creates a new OAuthHandler.
func NewOAuthHandler(deviceAuthAppService service.DeviceAuthAppService) *OAuthHandler {
	return &OAuthHandler{
		deviceAuthAppService: deviceAuthAppService,
	}
}

// DeviceAuthorizationRequest represents the request for the device authorization endpoint.
type DeviceAuthorizationRequest struct {
	ClientID string `form:"client_id" binding:"required"`
	Scope    string `form:"scope"`
}

// DeviceAuthorizationResponse is the successful response for the device authorization endpoint.
type DeviceAuthorizationResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// StartDeviceAuthorization handles the initiation of the device authorization flow.
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

// VerifyUserCodeRequest represents the request for the test-only verification endpoint.
type VerifyUserCodeRequest struct {
	UserCode string `json:"user_code" binding:"required"`
	Action   string `json:"action" binding:"required,oneof=approve deny"`
	TenantID string `json:"tenant_id"`
	Subject  string `json:"subject"`
}

// VerifyUserCode handles the user's approval or denial of the device authorization request.
// This is a test/dev-only endpoint.
func (h *OAuthHandler) VerifyUserCode(c *gin.Context) {
	var req VerifyUserCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

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
