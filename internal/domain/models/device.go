// Package models defines the domain models for the CBC authentication service.
// This file contains the Device domain model with business logic.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// Device represents a registered device in the authentication system.
// It contains device identification and metadata information.
type Device struct {
	// DeviceID is the unique identifier for the device
	DeviceID string `json:"device_id" db:"device_id"`

	// TenantID identifies which tenant this device belongs to
	TenantID string `json:"tenant_id" db:"tenant_id"`

	// DeviceType indicates the type of device (mobile, desktop, iot, etc.)
	DeviceType constants.DeviceType `json:"device_type" db:"device_type"`

	// OS is the operating system of the device
	OS string `json:"os" db:"os"`

	// OSVersion is the version of the operating system
	OSVersion string `json:"os_version" db:"os_version"`

	// AppVersion is the version of the client application
	AppVersion string `json:"app_version" db:"app_version"`

	// DeviceName is a user-friendly name for the device
	DeviceName string `json:"device_name,omitempty" db:"device_name"`

	// DisplayName is a user-friendly name for the device
	DisplayName string `json:"display_name,omitempty" db:"display_name"`

	// Platform is the operating system of the device
	Platform string `json:"platform,omitempty" db:"platform"`

	// AgentVersion is the version of the client application
	AgentVersion string `json:"agent_version,omitempty" db:"agent_version"`

	// DeviceFingerprint is a unique hash generated from device characteristics
	DeviceFingerprint string `json:"device_fingerprint" db:"device_fingerprint"`

	// TrustLevel indicates the trust level of the device (high, medium, low)
	TrustLevel constants.TrustLevel `json:"trust_level" db:"trust_level"`

	// Status indicates the current status of the device (active, suspended, revoked)
	Status constants.DeviceStatus `json:"status" db:"status"`

	// RegisteredAt is the timestamp when the device was first registered
	RegisteredAt time.Time `json:"registered_at" db:"registered_at"`

	// LastSeenAt is the timestamp of the last activity from this device
	LastSeenAt time.Time `json:"last_seen_at" db:"last_seen_at"`

	// LastIPAddress is the last known IP address of the device
	LastIPAddress string `json:"last_ip_address,omitempty" db:"last_ip_address"`

	// HardwareInfo contains additional hardware information (CPU, MAC, etc.)
	HardwareInfo string `json:"hardware_info,omitempty" db:"hardware_info"`

	// CreatedAt is the database record creation timestamp
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the database record last update timestamp
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// NewDevice creates a new Device instance with the provided parameters.
// It automatically sets RegisteredAt, CreatedAt, and UpdatedAt to the current time.
func NewDevice(deviceID, tenantID string, deviceType constants.DeviceType, os, osVersion, appVersion string) *Device {
	now := time.Now().UTC()
	return &Device{
		DeviceID:     deviceID,
		TenantID:     tenantID,
		DeviceType:   deviceType,
		OS:           os,
		OSVersion:    osVersion,
		AppVersion:   appVersion,
		TrustLevel:   constants.TrustLevelMedium, // Default trust level
		Status:       constants.DeviceStatusActive,
		RegisteredAt: now,
		LastSeenAt:   now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// GenerateFingerprint generates a unique fingerprint based on device characteristics.
// The fingerprint is a SHA256 hash of device information.
func (d *Device) GenerateFingerprint() string {
	// Combine device characteristics
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		d.DeviceID,
		d.DeviceType,
		d.OS,
		d.OSVersion,
		d.AppVersion,
		d.HardwareInfo,
	)

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(data))
	fingerprint := hex.EncodeToString(hash[:])

	// Update the device fingerprint
	d.DeviceFingerprint = fingerprint

	return fingerprint
}

// ValidateFingerprint checks if the provided fingerprint matches the device's fingerprint.
// Returns true if the fingerprints match.
func (d *Device) ValidateFingerprint(fingerprint string) bool {
	if d.DeviceFingerprint == "" {
		// Generate fingerprint if not set
		d.GenerateFingerprint()
	}
	return strings.EqualFold(d.DeviceFingerprint, fingerprint)
}

// IsActive checks if the device is currently active.
// Returns true if the device status is Active.
func (d *Device) IsActive() bool {
	return d.Status == constants.DeviceStatusActive
}

// IsSuspended checks if the device is suspended.
// Returns true if the device status is Suspended.
func (d *Device) IsSuspended() bool {
	return d.Status == constants.DeviceStatusSuspended
}

// IsRevoked checks if the device has been revoked.
// Returns true if the device status is Revoked.
func (d *Device) IsRevoked() bool {
	return d.Status == constants.DeviceStatusRevoked
}

// CanAuthenticate checks if the device can be used for authentication.
// A device can authenticate if it is active and has sufficient trust level.
func (d *Device) CanAuthenticate() bool {
	return d.IsActive() && d.TrustLevel != constants.TrustLevelNone
}

// UpdateLastSeen updates the LastSeenAt timestamp to the current time.
// This should be called whenever the device makes an authenticated request.
func (d *Device) UpdateLastSeen(ipAddress string) {
	now := time.Now().UTC()
	d.LastSeenAt = now
	d.UpdatedAt = now
	if ipAddress != "" {
		d.LastIPAddress = ipAddress
	}
}

// Suspend marks the device as suspended.
// Suspended devices cannot authenticate until reactivated.
func (d *Device) Suspend() {
	d.Status = constants.DeviceStatusSuspended
	d.UpdatedAt = time.Now().UTC()
}

// Activate marks the device as active.
// This can be used to reactivate a suspended device.
func (d *Device) Activate() {
	d.Status = constants.DeviceStatusActive
	d.UpdatedAt = time.Now().UTC()
}

// Revoke permanently revokes the device.
// Revoked devices cannot be reactivated and must be re-registered.
func (d *Device) Revoke() {
	d.Status = constants.DeviceStatusRevoked
	d.UpdatedAt = time.Now().UTC()
}

// SetTrustLevel updates the device trust level.
// Trust levels are used for risk-based authentication.
func (d *Device) SetTrustLevel(level constants.TrustLevel) {
	d.TrustLevel = level
	d.UpdatedAt = time.Now().UTC()
}

// IsInactive checks if the device has been inactive for a specified duration.
// Returns true if the device hasn't been seen for longer than the duration.
func (d *Device) IsInactive(duration time.Duration) bool {
	return time.Since(d.LastSeenAt) > duration
}

// GetDaysSinceRegistration returns the number of days since device registration.
func (d *Device) GetDaysSinceRegistration() int {
	return int(time.Since(d.RegisteredAt).Hours() / 24)
}

// GetDaysSinceLastSeen returns the number of days since the device was last seen.
func (d *Device) GetDaysSinceLastSeen() int {
	return int(time.Since(d.LastSeenAt).Hours() / 24)
}

// NeedsReAuthentication checks if the device should be prompted to re-authenticate.
// This is based on the last seen time and trust level.
func (d *Device) NeedsReAuthentication() bool {
	// High trust devices can go 30 days without re-auth
	// Medium trust devices can go 14 days
	// Low trust devices can go 7 days
	var maxInactiveDays int
	switch d.TrustLevel {
	case constants.TrustLevelHigh:
		maxInactiveDays = 30
	case constants.TrustLevelMedium:
		maxInactiveDays = 14
	case constants.TrustLevelLow:
		maxInactiveDays = 7
	default:
		return true // Unknown trust level, require re-auth
	}

	return d.GetDaysSinceLastSeen() > maxInactiveDays
}

// UpdateHardwareInfo updates the hardware information of the device.
func (d *Device) UpdateHardwareInfo(hwInfo string) {
	d.HardwareInfo = hwInfo
	d.UpdatedAt = time.Now().UTC()
	// Regenerate fingerprint with new hardware info
	d.GenerateFingerprint()
}

// ToMap converts the Device to a map for flexible serialization.
func (d *Device) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"device_id":          d.DeviceID,
		"tenant_id":          d.TenantID,
		"device_type":        string(d.DeviceType),
		"os":                 d.OS,
		"os_version":         d.OSVersion,
		"app_version":        d.AppVersion,
		"device_name":        d.DeviceName,
		"device_fingerprint": d.DeviceFingerprint,
		"trust_level":        string(d.TrustLevel),
		"status":             string(d.Status),
		"registered_at":      d.RegisteredAt.Unix(),
		"last_seen_at":       d.LastSeenAt.Unix(),
		"last_ip_address":    d.LastIPAddress,
		"hardware_info":      d.HardwareInfo,
		"created_at":         d.CreatedAt.Unix(),
		"updated_at":         d.UpdatedAt.Unix(),
		"is_active":          d.IsActive(),
		"can_authenticate":   d.CanAuthenticate(),
		"days_since_reg":     d.GetDaysSinceRegistration(),
		"days_since_seen":    d.GetDaysSinceLastSeen(),
	}
}

// Clone creates a deep copy of the Device.
func (d *Device) Clone() *Device {
	clone := *d
	return &clone
}

type TrustLevel string
type DeviceStatus string

//Personal.AI order the ending
