// Package handlers provides the HTTP handlers for the application.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application"
)

// riskUpdatePayload is the expected JSON structure for the risk update request.
type riskUpdatePayload struct {
	TenantID      string  `json:"tenant_id" binding:"required"`
	AnomalyScore  float64 `json:"anomaly_score" binding:"required,min=0,max=1"`
	PredictedThreat string `json:"predicted_threat" binding:"required"`
}

// MLInternalHandler handles requests for the internal machine learning API.
type MLInternalHandler struct {
	riskUpdateService application.RiskUpdateService
}

// NewMLInternalHandler creates a new MLInternalHandler.
func NewMLInternalHandler(riskUpdateService application.RiskUpdateService) *MLInternalHandler {
	return &MLInternalHandler{riskUpdateService: riskUpdateService}
}

// UpdateTenantRisk is the handler for POST /_internal/ml/risk.
// It receives a risk score update from an external ML system and
// updates the tenant's risk profile in the database.
func (h *MLInternalHandler) UpdateTenantRisk(c *gin.Context) {
	var payload riskUpdatePayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.riskUpdateService.UpdateTenantRisk(
		c.Request.Context(),
		payload.TenantID,
		payload.AnomalyScore,
		payload.PredictedThreat,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update risk profile"})
		return
	}

	c.Status(http.StatusNoContent)
}
