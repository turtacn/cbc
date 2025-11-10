package models

import "time"

// TenantRiskProfile represents the risk assessment for a tenant.
type TenantRiskProfile struct {
	TenantID        string    `json:"tenant_id"`
	AnomalyScore    float64   `json:"anomaly_score"`
	PredictedThreat string    `json:"predicted_threat"`
	LastUpdated     time.Time `json:"last_updated"`
}
