package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/pkg/errors"
)

// AuthHandler handles HTTP requests for authentication.
type AuthHandler struct {
	authService service.AuthAppService
	metrics     *monitoring.Metrics
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authService service.AuthAppService, metrics *monitoring.Metrics) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		metrics:     metrics,
	}
}

// IssueToken handles the request to issue a new token.
func (h *AuthHandler) IssueToken(c *gin.Context) {
	c.Set("trace_id", "test")
	startTime := time.Now()
	var req dto.TokenIssueRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		dto.SendError(c, errors.ErrInvalidRequest.WithError(err))
		return
	}

	if req.GrantType == "" || req.TenantID == uuid.Nil || req.DeviceID == "" {
		dto.SendError(c, errors.ErrInvalidRequest)
		return
	}

	result, err := h.authService.IssueToken(c.Request.Context(), &req)
	if err != nil {
		h.metrics.RecordTokenIssue(req.TenantID.String(), req.GrantType, "failure", time.Since(startTime))
		dto.SendError(c, err)
		return
	}

	h.metrics.RecordTokenIssue(req.TenantID.String(), req.GrantType, "success", time.Since(startTime))
	dto.SendSuccess(c, http.StatusOK, result)
}

// RefreshToken handles the request to refresh a token.
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	startTime := time.Now()
	var req dto.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		dto.SendError(c, errors.ErrInvalidRequest.WithError(err))
		return
	}

	result, err := h.authService.RefreshToken(c.Request.Context(), &req)
	if err != nil {
		// In a real implementation, we would extract tenantID from the old token for metrics
		h.metrics.RecordTokenIssue("", req.GrantType, "failure", time.Since(startTime))
		dto.SendError(c, err)
		return
	}

	h.metrics.RecordTokenIssue("", req.GrantType, "success", time.Since(startTime))
	dto.SendSuccess(c, http.StatusOK, result)
}

// RevokeToken handles the request to revoke a token.
func (h *AuthHandler) RevokeToken(c *gin.Context) {
	var req dto.TokenRevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		dto.SendError(c, errors.ErrInvalidRequest.WithError(err))
		return
	}

	if err := h.authService.RevokeToken(c.Request.Context(), &req); err != nil {
		dto.SendError(c, err)
		return
	}

	// In a real implementation, we would extract tenantID from the token for metrics
	h.metrics.RecordTokenRevocation("")
	dto.SendSuccess(c, http.StatusOK, gin.H{"status": "ok"})
}

// GetJWKS handles the request to get the JSON Web Key Set for a tenant.
func (h *AuthHandler) GetJWKS(c *gin.Context) {
	// tenantID := c.Param("tenant_id")
	// This would call a service to get the public keys for the tenant
	// and format them in JWKS format.
	c.JSON(http.StatusOK, gin.H{"keys": []interface{}{}})
}

//Personal.AI order the ending
