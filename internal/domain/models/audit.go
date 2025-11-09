// Package models defines the core domain models.
package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditEvent represents a security-sensitive event to be logged.
type AuditEvent struct {
	ID         uuid.UUID `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	TenantID   string    `json:"tenant_id"`
	Actor      string    `json:"actor,omitempty"`
	Action     string    `json:"action"`
	Target     string    `json:"target,omitempty"`
	IPAddress  string    `json:"ip_address"`
	Details    string    `json:"details,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	EventType  string    `json:"event_type"`
	Success    bool      `json:"success"`
}
