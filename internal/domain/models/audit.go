// Package models defines the core domain models.
package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditEvent represents a security-sensitive event to be logged.
type AuditEvent struct {
	ID        uuid.UUID `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
	ClientIP  string    `json:"client_ip"`
	EventType string    `json:"event_type"`
	Success   bool      `json:"success"`
	Details   string    `json:"details,omitempty"`
}
