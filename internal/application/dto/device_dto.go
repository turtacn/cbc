package dto

import (
	"time"

	"github.com/google/uuid"
)

// DeviceRegisterRequest represents the request to register a new device.
type DeviceRegisterRequest struct {
	DeviceID   string    `json:"device_id" validate:"required"`
	TenantID   uuid.UUID `json:"tenant_id" validate:"required,uuid"`
	DeviceType string    `json:"device_type" validate:"required"`
	DeviceName string    `json:"device_name,omitempty"`
	OS         string    `json:"os" validate:"required"`
	AppVersion string    `json:"app_version" validate:"required"`
}

// DeviceUpdateRequest represents the request to update a device's information.
type DeviceUpdateRequest struct {
	DeviceName *string `json:"device_name,omitempty"`
	AppVersion *string `json:"app_version,omitempty"`
}

// DeviceResponse represents a device's information in the API response.
type DeviceResponse struct {
	DeviceID     string    `json:"device_id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	DeviceType   string    `json:"device_type"`
	DeviceName   string    `json:"device_name,omitempty"`
	OS           string    `json:"os"`
	AppVersion   string    `json:"app_version"`
	Status       string    `json:"status"`
	RegisteredAt time.Time `json:"registered_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}
//Personal.AI order the ending