// Package handlers provides the HTTP handlers for the application.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/application"
)

// riskUpdatePayload defines the expected JSON structure for the incoming risk update request from the ML system.
// The `binding` tags are used by Gin for automatic request validation.
// riskUpdatePayload 定义了来自 ML 系统的传入风险更新请求的预期 JSON 结构。
// `binding` 标签由 Gin 用于自动请求验证。
type riskUpdatePayload struct {
	TenantID        string  `json:"tenant_id" binding:"required"`
	AnomalyScore    float64 `json:"anomaly_score" binding:"required,min=0,max=1"`
	PredictedThreat string  `json:"predicted_threat" binding:"required"`
}

// MLInternalHandler provides HTTP handlers for the internal-only machine learning API endpoints.
// These endpoints are not exposed to the public and are used for services like the risk oracle to push data.
// MLInternalHandler 为仅限内部的机器学习 API 端点提供 HTTP 处理程序。
// 这些端点不对公众公开，用于风险预言机等服务推送数据。
type MLInternalHandler struct {
	riskUpdateService application.RiskUpdateService
}

// NewMLInternalHandler creates a new instance of MLInternalHandler.
// NewMLInternalHandler 创建一个新的 MLInternalHandler 实例。
func NewMLInternalHandler(riskUpdateService application.RiskUpdateService) *MLInternalHandler {
	return &MLInternalHandler{riskUpdateService: riskUpdateService}
}

// UpdateTenantRisk is the handler for `POST /_internal/ml/risk`.
// It receives a risk score update from an external ML system, validates the payload,
// and invokes the application service to update the tenant's risk profile.
// UpdateTenantRisk 是 `POST /_internal/ml/risk` 的处理程序。
// 它从外部 ML 系统接收风险评分更新，验证有效负载，并调用应用程序服务来更新租户的风险配置文件。
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
		// In a real-world scenario, you'd use a structured error response
		// and map the domain error to a proper HTTP status code.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update risk profile"})
		return
	}

	c.Status(http.StatusNoContent)
}
