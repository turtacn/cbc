package models

import (
	"time"

	"github.com/google/uuid"
)

// KLREvent represents a key lifecycle event.
type KLREvent struct {
	EventID        uuid.UUID `json:"event_id"`
	KeyID          string    `json:"key_id"`
	TenantID       string    `json:"tenant_id"`
	Status         string    `json:"status"`
	EventTimestamp time.Time `json:"event_timestamp"`
	Metadata       string    `json:"metadata"`
	Version        int       `json:"version"`
}

// PolicyRequest represents a request to the policy engine.
type PolicyRequest struct {
	ComplianceClass    string             `json:"compliance_class"`
	KeySize            int                `json:"key_size"`
	CurrentRiskProfile *TenantRiskProfile `json:"current_risk_profile,omitempty"`
}
