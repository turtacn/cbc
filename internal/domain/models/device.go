package models

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Device represents the domain model for a registered device.
type Device struct {
	ID           uuid.UUID
	DeviceID     string // Unique identifier provided by the agent
	TenantID     uuid.UUID
	DeviceType   string
	DeviceName   string
	OS           string
	AppVersion   string
	Fingerprint  string
	Status       string // e.g., "active", "suspended", "untrusted"
	RegisteredAt time.Time
	LastSeenAt   time.Time
}

// NewDevice creates a new device instance.
func NewDevice(deviceID string, tenantID uuid.UUID, deviceType, os, appVersion string) *Device {
	now := time.Now().UTC()
	device := &Device{
		ID:           uuid.New(),
		DeviceID:     deviceID,
		TenantID:     tenantID,
		DeviceType:   deviceType,
		OS:           os,
		AppVersion:   appVersion,
		Status:       "active",
		RegisteredAt: now,
		LastSeenAt:   now,
	}
	device.Fingerprint = device.GenerateFingerprint()
	return device
}

// GenerateFingerprint creates a stable hash based on device characteristics.
func (d *Device) GenerateFingerprint() string {
	// A more robust implementation would include hardware IDs (e.g., TPM-bound keys).
	// For this version, we use a combination of software and identifiers.
	data := fmt.Sprintf("%s:%s:%s:%s:%s", d.TenantID, d.DeviceID, d.DeviceType, d.OS, d.AppVersion)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// IsActive checks if the device is in an active state.
func (d *Device) IsActive() bool {
	return d.Status == "active"
}

// UpdateLastSeen updates the device's last seen timestamp.
func (d *Device) UpdateLastSeen() {
	d.LastSeenAt = time.Now().UTC()
}
//Personal.AI order the ending