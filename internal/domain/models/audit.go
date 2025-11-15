// Package models defines the core domain models.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AuditEvent represents a security-sensitive event to be logged for auditing purposes.
// It captures who did what, to what, when, and from where, along with the outcome.
// @Description AuditEvent represents a security-sensitive event to be logged.
type AuditEvent struct {
	// ID is the unique identifier for the audit event.
	// @Description ID is the unique identifier for the audit event.
	ID uuid.UUID `json:"id"`
	// Timestamp is the time the event occurred.
	// @Description Timestamp is the time the event occurred.
	Timestamp time.Time `json:"timestamp"`
	// TenantID is the identifier of the tenant in which the event occurred.
	// @Description TenantID is the identifier of the tenant in which the event occurred.
	TenantID string `json:"tenant_id"`
	// Actor is the identifier of the user or system that performed the action.
	// @Description Actor is the identifier of the user or system that performed the action.
	Actor string `json:"actor,omitempty"`
	// Action is the specific action that was performed (e.g., "login", "create_key").
	// @Description Action is the specific action that was performed.
	Action string `json:"action"`
	// Target is the identifier of the resource that was affected by the action.
	// @Description Target is the identifier of the resource that was affected by the action.
	Target string `json:"target,omitempty"`
	// IPAddress is the source IP address from which the action was initiated.
	// @Description IPAddress is the source IP address from which the action was initiated.
	IPAddress string `json:"ip_address"`
	// Details provides additional information about the event.
	// @Description Details provides additional information about the event.
	Details string `json:"details,omitempty"`
	// StatusCode is the HTTP status code associated with the event, if applicable.
	// @Description StatusCode is the HTTP status code associated with the event.
	StatusCode int `json:"status_code,omitempty"`
	// EventType is a high-level classification of the event (e.g., "authentication", "authorization").
	// @Description EventType is a high-level classification of the event.
	EventType string `json:"event_type"`
	// Success indicates whether the action was successful.
	// @Description Success indicates whether the action was successful.
	Success bool `json:"success"`
	// Metadata provides a flexible way to store additional, action-specific context.
	// @Description Metadata provides a flexible way to store additional, action-specific context.
	Metadata Metadata `json:"metadata,omitempty" gorm:"type:json"`
}

type Metadata map[string]string

func (m Metadata) Value() (driver.Value, error) {
	return json.Marshal(m)
}

func (m *Metadata) Scan(value interface{}) error {
	return json.Unmarshal(value.([]byte), m)
}
