// Package models defines the domain models for the CBC authentication service.
// This file contains the Tenant domain model with business logic.
package models

import (
	"encoding/json"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// Tenant represents a tenant organization in the multi-tenant authentication system.
// Each tenant has its own isolated configuration and policies.
type Tenant struct {
	// TenantID is the unique identifier for the tenant
	TenantID string `json:"tenant_id" db:"tenant_id"`

	// TenantName is the display name of the tenant organization
	TenantName string `json:"tenant_name" db:"tenant_name"`

	// ComplianceClass is the compliance class of the tenant
	ComplianceClass string `json:"compliance_class" db:"compliance_class"`

	// Status indicates the current status of the tenant (active, suspended, deleted)
	Status constants.TenantStatus `json:"status" db:"status"`

	// KeyRotationPolicy defines the key rotation configuration
	KeyRotationPolicy KeyRotationPolicy `json:"key_rotation_policy" db:"key_rotation_policy"`

	// RateLimitConfig defines the rate limiting configuration
	RateLimitConfig RateLimitConfig `json:"rate_limit_config" db:"rate_limit_config"`

	// TokenTTLConfig defines the token time-to-live configuration
	TokenTTLConfig TokenTTLConfig `json:"token_ttl_config" db:"token_ttl_config"`

	// SecurityPolicy defines additional security requirements
	SecurityPolicy SecurityPolicy `json:"security_policy" db:"security_policy"`

	// CreatedAt is the timestamp when the tenant was created
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the timestamp of the last update
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// DeletedAt is the timestamp when the tenant was soft-deleted (null if not deleted)
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// KeyRotationPolicy defines the key rotation configuration for a tenant.
type KeyRotationPolicy struct {
	// ActiveKeyID is the current active key ID for signing
	ActiveKeyID string `json:"active_key_id"`

	// RotationIntervalDays is the number of days between automatic key rotations
	RotationIntervalDays int `json:"rotation_interval_days"`

	// LastRotatedAt is the timestamp of the last key rotation
	LastRotatedAt time.Time `json:"last_rotated_at"`

	// NextRotationAt is the scheduled timestamp for the next rotation
	NextRotationAt time.Time `json:"next_rotation_at"`

	// DeprecatedKeyIDs is a list of deprecated keys still valid for verification
	DeprecatedKeyIDs []string `json:"deprecated_key_ids,omitempty"`

	// AutoRotationEnabled indicates if automatic rotation is enabled
	AutoRotationEnabled bool `json:"auto_rotation_enabled"`
}

// RateLimitConfig defines the rate limiting configuration for a tenant.
type RateLimitConfig struct {
	// GlobalQPS is the maximum requests per second for the entire tenant
	GlobalQPS int `json:"global_qps"`

	// PerDeviceQPS is the maximum requests per second per device
	PerDeviceQPS int `json:"per_device_qps"`

	// PerDevicePerMinute is the maximum requests per minute per device
	PerDevicePerMinute int `json:"per_device_per_minute"`

	// RequestsPerMinute is the maximum requests per minute allowed
	RequestsPerMinute int `json:"requests_per_minute"`

	// BurstSize is the maximum burst size allowed
	BurstSize int `json:"burst_size"`

	// Enabled indicates if rate limiting is enabled
	Enabled bool `json:"enabled"`
}

// TokenTTLConfig defines the token time-to-live configuration for a tenant.
type TokenTTLConfig struct {
	// AccessTokenTTLSeconds is the lifetime of access tokens in seconds
	AccessTokenTTLSeconds int `json:"access_token_ttl_seconds"`

	// RefreshTokenTTLSeconds is the lifetime of refresh tokens in seconds
	RefreshTokenTTLSeconds int `json:"refresh_token_ttl_seconds"`

	// OneTimeRefreshToken indicates if refresh tokens are one-time use
	OneTimeRefreshToken bool `json:"one_time_refresh_token"`
}

// SecurityPolicy defines additional security requirements for a tenant.
type SecurityPolicy struct {
	// RequireDeviceFingerprint indicates if device fingerprint validation is required
	RequireDeviceFingerprint bool `json:"require_device_fingerprint"`

	// RequireMTLS indicates if mutual TLS is required
	RequireMTLS bool `json:"require_mtls"`

	// AllowedIPRanges is a list of allowed IP ranges (CIDR notation)
	AllowedIPRanges []string `json:"allowed_ip_ranges,omitempty"`

	// MinTrustLevel is the minimum trust level required for authentication
	MinTrustLevel constants.TrustLevel `json:"min_trust_level"`

	// MaxDevicesPerTenant is the maximum number of devices allowed
	MaxDevicesPerTenant int `json:"max_devices_per_tenant"`
}

// NewTenant creates a new Tenant instance with default configuration.
func NewTenant(tenantID, tenantName string) *Tenant {
	now := time.Now().UTC()
	return &Tenant{
		TenantID:   tenantID,
		TenantName: tenantName,
		Status:     constants.TenantStatusActive,
		KeyRotationPolicy: KeyRotationPolicy{
			RotationIntervalDays: 90, // Default 90 days
			AutoRotationEnabled:  true,
			LastRotatedAt:        now,
			NextRotationAt:       now.AddDate(0, 0, 90),
		},
		RateLimitConfig: RateLimitConfig{
			GlobalQPS:          100000, // Default 100k QPS
			PerDeviceQPS:       10,
			PerDevicePerMinute: 600,
			BurstSize:          1000,
			Enabled:            true,
		},
		TokenTTLConfig: TokenTTLConfig{
			AccessTokenTTLSeconds:  900,     // 15 minutes
			RefreshTokenTTLSeconds: 2592000, // 30 days
			OneTimeRefreshToken:    true,
		},
		SecurityPolicy: SecurityPolicy{
			RequireDeviceFingerprint: true,
			RequireMTLS:              false,
			MinTrustLevel:            constants.TrustLevelLow,
			MaxDevicesPerTenant:      10000000, // 10 million devices
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// IsActive checks if the tenant is currently active.
func (t *Tenant) IsActive() bool {
	return t.Status == constants.TenantStatusActive && t.DeletedAt == nil
}

// IsSuspended checks if the tenant is suspended.
func (t *Tenant) IsSuspended() bool {
	return t.Status == constants.TenantStatusSuspended
}

// IsDeleted checks if the tenant has been deleted.
func (t *Tenant) IsDeleted() bool {
	return t.DeletedAt != nil
}

// GetAccessTokenTTL returns the access token TTL as a duration.
func (t *Tenant) GetAccessTokenTTL() time.Duration {
	return time.Duration(t.TokenTTLConfig.AccessTokenTTLSeconds) * time.Second
}

// GetRefreshTokenTTL returns the refresh token TTL as a duration.
func (t *Tenant) GetRefreshTokenTTL() time.Duration {
	return time.Duration(t.TokenTTLConfig.RefreshTokenTTLSeconds) * time.Second
}

// GetRateLimitThreshold returns the rate limit threshold for a specific scope.
func (t *Tenant) GetRateLimitThreshold(scope string) int {
	switch scope {
	case "global":
		return t.RateLimitConfig.GlobalQPS
	case "device":
		return t.RateLimitConfig.PerDeviceQPS
	case "device_minute":
		return t.RateLimitConfig.PerDevicePerMinute
	default:
		return t.RateLimitConfig.PerDeviceQPS
	}
}

// NeedsKeyRotation checks if the tenant needs key rotation based on policy.
func (t *Tenant) NeedsKeyRotation() bool {
	if !t.KeyRotationPolicy.AutoRotationEnabled {
		return false
	}
	return time.Now().UTC().After(t.KeyRotationPolicy.NextRotationAt)
}

// ScheduleNextKeyRotation updates the next rotation timestamp.
func (t *Tenant) ScheduleNextKeyRotation() {
	now := time.Now().UTC()
	days := t.KeyRotationPolicy.RotationIntervalDays
	if days <= 0 {
		days = 90 // Default to 90 days
	}
	t.KeyRotationPolicy.NextRotationAt = now.AddDate(0, 0, days)
	t.UpdatedAt = now
}

// UpdateActiveKey updates the active key ID and schedules next rotation.
func (t *Tenant) UpdateActiveKey(newKeyID string) {
	now := time.Now().UTC()

	// Move current active key to deprecated list
	if t.KeyRotationPolicy.ActiveKeyID != "" {
		t.KeyRotationPolicy.DeprecatedKeyIDs = append(
			t.KeyRotationPolicy.DeprecatedKeyIDs,
			t.KeyRotationPolicy.ActiveKeyID,
		)
	}

	// Update active key
	t.KeyRotationPolicy.ActiveKeyID = newKeyID
	t.KeyRotationPolicy.LastRotatedAt = now

	// Schedule next rotation
	t.ScheduleNextKeyRotation()

	t.UpdatedAt = now
}

// RemoveDeprecatedKey removes a key from the deprecated list.
func (t *Tenant) RemoveDeprecatedKey(keyID string) {
	var filtered []string
	for _, k := range t.KeyRotationPolicy.DeprecatedKeyIDs {
		if k != keyID {
			filtered = append(filtered, k)
		}
	}
	t.KeyRotationPolicy.DeprecatedKeyIDs = filtered
	t.UpdatedAt = time.Now().UTC()
}

// Suspend marks the tenant as suspended.
func (t *Tenant) Suspend() {
	t.Status = constants.TenantStatusSuspended
	t.UpdatedAt = time.Now().UTC()
}

// Activate marks the tenant as active.
func (t *Tenant) Activate() {
	t.Status = constants.TenantStatusActive
	t.UpdatedAt = time.Now().UTC()
}

// SoftDelete marks the tenant as deleted (soft delete).
func (t *Tenant) SoftDelete() {
	now := time.Now().UTC()
	t.DeletedAt = &now
	t.Status = constants.TenantStatusDeleted
	t.UpdatedAt = now
}

// ValidateIPAddress checks if an IP address is allowed based on policy.
func (t *Tenant) ValidateIPAddress(ipAddr string) bool {
	if len(t.SecurityPolicy.AllowedIPRanges) == 0 {
		return true // No IP restrictions
	}

	// TODO: Implement CIDR matching
	// For now, simple implementation
	for _, allowedRange := range t.SecurityPolicy.AllowedIPRanges {
		if allowedRange == ipAddr || allowedRange == "0.0.0.0/0" {
			return true
		}
	}

	return false
}

// ValidateTrustLevel checks if a device trust level meets the minimum requirement.
func (t *Tenant) ValidateTrustLevel(deviceTrustLevel constants.TrustLevel) bool {
	trustLevels := map[constants.TrustLevel]int{
		constants.TrustLevelNone:   0,
		constants.TrustLevelLow:    1,
		constants.TrustLevelMedium: 2,
		constants.TrustLevelHigh:   3,
	}

	deviceLevel := trustLevels[deviceTrustLevel]
	minLevel := trustLevels[t.SecurityPolicy.MinTrustLevel]

	return deviceLevel >= minLevel
}

// ToJSON converts the tenant to JSON string.
func (t *Tenant) ToJSON() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON populates the tenant from JSON string.
func (t *Tenant) FromJSON(jsonStr string) error {
	return json.Unmarshal([]byte(jsonStr), t)
}

// ToMap converts the Tenant to a map for flexible serialization.
func (t *Tenant) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"tenant_id":            t.TenantID,
		"tenant_name":          t.TenantName,
		"status":               string(t.Status),
		"key_rotation_policy":  t.KeyRotationPolicy,
		"rate_limit_config":    t.RateLimitConfig,
		"token_ttl_config":     t.TokenTTLConfig,
		"security_policy":      t.SecurityPolicy,
		"created_at":           t.CreatedAt.Unix(),
		"updated_at":           t.UpdatedAt.Unix(),
		"is_active":            t.IsActive(),
		"needs_key_rotation":   t.NeedsKeyRotation(),
		"access_token_ttl_min": t.TokenTTLConfig.AccessTokenTTLSeconds / 60,
		"refresh_token_ttl_days": t.TokenTTLConfig.RefreshTokenTTLSeconds / 86400,
	}

	if t.DeletedAt != nil {
		m["deleted_at"] = t.DeletedAt.Unix()
	}

	return m
}

// Clone creates a deep copy of the Tenant.
func (t *Tenant) Clone() *Tenant {
	clone := *t

	// Deep copy slices
	if len(t.KeyRotationPolicy.DeprecatedKeyIDs) > 0 {
		clone.KeyRotationPolicy.DeprecatedKeyIDs = make([]string, len(t.KeyRotationPolicy.DeprecatedKeyIDs))
		copy(clone.KeyRotationPolicy.DeprecatedKeyIDs, t.KeyRotationPolicy.DeprecatedKeyIDs)
	}

	if len(t.SecurityPolicy.AllowedIPRanges) > 0 {
		clone.SecurityPolicy.AllowedIPRanges = make([]string, len(t.SecurityPolicy.AllowedIPRanges))
		copy(clone.SecurityPolicy.AllowedIPRanges, t.SecurityPolicy.AllowedIPRanges)
	}

	return &clone
}

//Personal.AI order the ending
