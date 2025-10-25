package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/pkg/constants"
)

// AuditLog represents a single audit trail event.
type AuditLog struct {
	EventID    uuid.UUID
	TenantID   uuid.UUID
	DeviceID   *uuid.UUID // Can be nil for tenant-level events
	ActorID    string     // Who performed the action (e.g., DeviceID, UserID, System)
	EventType  constants.AuditEventType
	Result     string // "success" or "failure"
	ResultCode constants.ErrorCode
	IPAddress  string
	UserAgent  string
	TraceID    string
	Message    string
	Metadata   json.RawMessage // Flexible field for event-specific data
	Timestamp  time.Time
}

// NewAuditLog creates a new audit log entry.
func NewAuditLog(
	tenantID uuid.UUID,
	eventType constants.AuditEventType,
	result string,
	message string,
) *AuditLog {
	return &AuditLog{
		EventID:   uuid.New(),
		TenantID:  tenantID,
		EventType: eventType,
		Result:    result,
		Message:   message,
		Timestamp: time.Now().UTC(),
	}
}

// WithDevice sets the device ID for the audit log.
func (a *AuditLog) WithDevice(deviceID uuid.UUID) *AuditLog {
	a.DeviceID = &deviceID
	return a
}

// WithActor sets the actor ID for the audit log.
func (a *AuditLog) WithActor(actorID string) *AuditLog {
	a.ActorID = actorID
	return a
}

// WithContextInfo sets context-related information.
func (a *AuditLog) WithContextInfo(ip, ua, traceID string) *AuditLog {
	a.IPAddress = ip
	a.UserAgent = ua
	a.TraceID = traceID
	return a
}

// WithMetadata sets JSON metadata for the audit log.
func (a *AuditLog) WithMetadata(data interface{}) *AuditLog {
	jsonData, err := json.Marshal(data)
	if err == nil {
		a.Metadata = jsonData
	}
	return a
}

// WithResultCode sets the specific error code for failed events.
func (a *AuditLog) WithResultCode(code constants.ErrorCode) *AuditLog {
	a.ResultCode = code
	return a
}

//Personal.AI order the ending
