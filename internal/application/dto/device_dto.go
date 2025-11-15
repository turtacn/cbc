package dto

import "time"

// DeviceRegisterRequest defines the structure for a device registration request.
// It includes fields for both MGR assertion and legacy registration flows.
type DeviceRegisterRequest struct {
	GrantType           string `json:"grant_type" binding:"required"`
	ClientID            string `json:"client_id" binding:"required"`
	ClientAssertionType string `json:"client_assertion_type" binding:"required,eq=urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
	ClientAssertion     string `json:"client_assertion" binding:"required"`
	TenantID            string `json:"tenant_id" binding:"required"`
	AgentID             string `json:"agent_id" binding:"required"`
	DeviceFingerprint   string `json:"device_fingerprint" binding:"required"`
	DeviceName          string `json:"device_name"`
	DeviceType          string `json:"device_type"`
}

// DeviceUpdateRequest defines the structure for a device update request.
type DeviceUpdateRequest struct {
	DeviceName string `json:"device_name"`
	Status     string `json:"status"`
	AgentID    string `json:"agent_id"`
}

// DeviceResponse defines the structure for a device response.
type DeviceResponse struct {
	DeviceID          string    `json:"device_id"`
	AgentID           string    `json:"agent_id"`
	TenantID          string    `json:"tenant_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	DeviceName        string    `json:"device_name"`
	DeviceType        string    `json:"device_type,omitempty"`
	TrustLevel        string    `json:"trust_level,omitempty"`
	Status            string    `json:"status"`
	RegisteredAt      time.Time `json:"registered_at,omitempty"`
	LastSeenAt        time.Time `json:"last_seen_at,omitempty"`
	RefreshToken      string    `json:"refresh_token,omitempty"`
}
