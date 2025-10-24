// Package models defines the domain models for the CBC authentication service.
// This file contains the AuditLog domain model with business logic.
package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// AuditLog represents an audit log entry for tracking authentication events.
// It provides comprehensive logging for security monitoring and compliance.
type AuditLog struct {
	// EventID is the unique identifier for this audit event
	EventID string `json:"event_id" db:"event_id"`

	// TenantID identifies which tenant this event belongs to
	TenantID string `json:"tenant_id" db:"tenant_id"`

	// DeviceID identifies the device involved in the event (if applicable)
	DeviceID string `json:"device_id,omitempty" db:"device_id"`

	// UserID identifies the user involved in the event (if applicable)
	UserID string `json:"user_id,omitempty" db:"user_id"`

	// EventType indicates the type of event (token_issue, token_refresh, etc.)
	EventType constants.AuditEventType `json:"event_type" db:"event_type"`

	// Result indicates the outcome of the event (success, failure)
	Result constants.AuditResult `json:"result" db:"result"`

	// ErrorCode contains the error code if the event failed
	ErrorCode string `json:"error_code,omitempty" db:"error_code"`

	// ErrorMessage contains the error message if the event failed
	ErrorMessage string `json:"error_message,omitempty" db:"error_message"`

	// IPAddress is the client IP address
	IPAddress string `json:"ip_address,omitempty" db:"ip_address"`

	// UserAgent is the client user agent string
	UserAgent string `json:"user_agent,omitempty" db:"user_agent"`

	// RequestID is the unique request identifier for correlation
	RequestID string `json:"request_id,omitempty" db:"request_id"`

	// SessionID is the session identifier (if applicable)
	SessionID string `json:"session_id,omitempty" db:"session_id"`

	// Metadata contains additional event-specific information
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`

	// Timestamp is when the event occurred
	Timestamp time.Time `json:"timestamp" db:"timestamp"`

	// CreatedAt is the database record creation timestamp
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// NewAuditLog creates a new AuditLog instance with the provided parameters.
func NewAuditLog(eventID, tenantID string, eventType constants.AuditEventType, result constants.AuditResult) *AuditLog {
	now := time.Now().UTC()
	return &AuditLog{
		EventID:   eventID,
		TenantID:  tenantID,
		EventType: eventType,
		Result:    result,
		Metadata:  make(map[string]interface{}),
		Timestamp: now,
		CreatedAt: now,
	}
}

// WithDevice adds device information to the audit log.
func (a *AuditLog) WithDevice(deviceID string) *AuditLog {
	a.DeviceID = deviceID
	return a
}

// WithUser adds user information to the audit log.
func (a *AuditLog) WithUser(userID string) *AuditLog {
	a.UserID = userID
	return a
}

// WithError adds error information to the audit log.
func (a *AuditLog) WithError(errorCode, errorMessage string) *AuditLog {
	a.ErrorCode = errorCode
	a.ErrorMessage = errorMessage
	a.Result = constants.AuditResultFailure
	return a
}

// WithIP adds IP address to the audit log.
func (a *AuditLog) WithIP(ipAddress string) *AuditLog {
	a.IPAddress = ipAddress
	return a
}

// WithUserAgent adds user agent to the audit log.
func (a *AuditLog) WithUserAgent(userAgent string) *AuditLog {
	a.UserAgent = userAgent
	return a
}

// WithRequestID adds request ID to the audit log.
func (a *AuditLog) WithRequestID(requestID string) *AuditLog {
	a.RequestID = requestID
	return a
}

// WithSessionID adds session ID to the audit log.
func (a *AuditLog) WithSessionID(sessionID string) *AuditLog {
	a.SessionID = sessionID
	return a
}

// AddMetadata adds a key-value pair to the metadata.
func (a *AuditLog) AddMetadata(key string, value interface{}) *AuditLog {
	if a.Metadata == nil {
		a.Metadata = make(map[string]interface{})
	}
	a.Metadata[key] = value
	return a
}

// AddMetadataMap adds multiple key-value pairs to the metadata.
func (a *AuditLog) AddMetadataMap(data map[string]interface{}) *AuditLog {
	if a.Metadata == nil {
		a.Metadata = make(map[string]interface{})
	}
	for k, v := range data {
		a.Metadata[k] = v
	}
	return a
}

// IsSuccess checks if the audit event was successful.
func (a *AuditLog) IsSuccess() bool {
	return a.Result == constants.AuditResultSuccess
}

// IsFailure checks if the audit event failed.
func (a *AuditLog) IsFailure() bool {
	return a.Result == constants.AuditResultFailure
}

// GetMetadataString returns a metadata value as string.
func (a *AuditLog) GetMetadataString(key string) (string, bool) {
	if a.Metadata == nil {
		return "", false
	}
	val, exists := a.Metadata[key]
	if !exists {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// GetMetadataInt returns a metadata value as int.
func (a *AuditLog) GetMetadataInt(key string) (int, bool) {
	if a.Metadata == nil {
		return 0, false
	}
	val, exists := a.Metadata[key]
	if !exists {
		return 0, false
	}

	switch v := val.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

// ToJSON converts the audit log to JSON string.
func (a *AuditLog) ToJSON() (string, error) {
	data, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("failed to marshal audit log to JSON: %w", err)
	}
	return string(data), nil
}

// FromJSON populates the audit log from JSON string.
func (a *AuditLog) FromJSON(jsonStr string) error {
	err := json.Unmarshal([]byte(jsonStr), a)
	if err != nil {
		return fmt.Errorf("failed to unmarshal audit log from JSON: %w", err)
	}
	return nil
}

// ToMap converts the AuditLog to a map for flexible serialization.
func (a *AuditLog) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"event_id":   a.EventID,
		"tenant_id":  a.TenantID,
		"event_type": string(a.EventType),
		"result":     string(a.Result),
		"timestamp":  a.Timestamp.Unix(),
		"created_at": a.CreatedAt.Unix(),
	}

	if a.DeviceID != "" {
		m["device_id"] = a.DeviceID
	}

	if a.UserID != "" {
		m["user_id"] = a.UserID
	}

	if a.ErrorCode != "" {
		m["error_code"] = a.ErrorCode
		m["error_message"] = a.ErrorMessage
	}

	if a.IPAddress != "" {
		m["ip_address"] = a.IPAddress
	}

	if a.UserAgent != "" {
		m["user_agent"] = a.UserAgent
	}

	if a.RequestID != "" {
		m["request_id"] = a.RequestID
	}

	if a.SessionID != "" {
		m["session_id"] = a.SessionID
	}

	if len(a.Metadata) > 0 {
		m["metadata"] = a.Metadata
	}

	return m
}

// GetSeverity returns the severity level of the audit event.
// This can be used for alerting and monitoring.
func (a *AuditLog) GetSeverity() string {
	// Failures are higher severity
	if a.IsFailure() {
		switch a.EventType {
		case constants.AuditEventTokenIssue,
			constants.AuditEventTokenRefresh,
			constants.AuditEventDeviceRegister:
			return "WARNING"
		case constants.AuditEventTokenRevoke,
			constants.AuditEventDeviceRevoke,
			constants.AuditEventKeyRotation:
			return "CRITICAL"
		default:
			return "ERROR"
		}
	}

	// Successes have lower severity
	switch a.EventType {
	case constants.AuditEventKeyRotation,
		constants.AuditEventDeviceRevoke:
		return "INFO"
	default:
		return "DEBUG"
	}
}

// ShouldAlert determines if this audit event should trigger an alert.
func (a *AuditLog) ShouldAlert() bool {
	// Alert on all failures
	if a.IsFailure() {
		return true
	}

	// Alert on certain successful events
	switch a.EventType {
	case constants.AuditEventTokenRevoke,
		constants.AuditEventDeviceRevoke,
		constants.AuditEventKeyRotation:
		return true
	default:
		return false
	}
}

// GetDescription returns a human-readable description of the audit event.
func (a *AuditLog) GetDescription() string {
	action := string(a.EventType)
	result := string(a.Result)

	desc := fmt.Sprintf("%s %s", action, result)

	if a.IsFailure() && a.ErrorCode != "" {
		desc += fmt.Sprintf(" with error %s", a.ErrorCode)
	}

	if a.DeviceID != "" {
		desc += fmt.Sprintf(" for device %s", a.DeviceID)
	}

	if a.IPAddress != "" {
		desc += fmt.Sprintf(" from IP %s", a.IPAddress)
	}

	return desc
}

// Clone creates a deep copy of the AuditLog.
func (a *AuditLog) Clone() *AuditLog {
	clone := *a

	// Deep copy metadata
	if len(a.Metadata) > 0 {
		clone.Metadata = make(map[string]interface{})
		for k, v := range a.Metadata {
			clone.Metadata[k] = v
		}
	}

	return &clone
}

// Validate checks if the audit log has all required fields.
func (a *AuditLog) Validate() error {
	if a.EventID == "" {
		return fmt.Errorf("event_id is required")
	}

	if a.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	if a.EventType == "" {
		return fmt.Errorf("event_type is required")
	}

	if a.Result == "" {
		return fmt.Errorf("result is required")
	}

	if a.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}

	return nil
}

//Personal.AI order the ending
