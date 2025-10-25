package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/pkg/constants"
)

// KeyRotationPolicy defines the policy for rotating tenant keys.
type KeyRotationPolicy struct {
	RotationPeriodDays int    `json:"rotation_period_days"`
	ActiveKeyID        string `json:"active_key_id"`
	Algorithm          string `json:"algorithm"`
}

// RateLimitConfig defines the rate limiting settings for a tenant.
type RateLimitConfig struct {
	Enabled        bool `json:"enabled"`
	RequestsPerSec int  `json:"requests_per_sec"`
	Burst          int  `json:"burst"`
}

// Tenant represents the domain model for a tenant.
type Tenant struct {
	ID                uuid.UUID
	TenantName        string
	Status            string // "active", "suspended", "deleted"
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	KeyRotationPolicy KeyRotationPolicy
	RateLimitConfig   RateLimitConfig
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// NewTenant creates a new tenant with default settings.
func NewTenant(name string) *Tenant {
	return &Tenant{
		ID:              uuid.New(),
		TenantName:      name,
		Status:          "active",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour, // 30 days
		KeyRotationPolicy: KeyRotationPolicy{
			RotationPeriodDays: 90,
			Algorithm:          string(constants.RS256),
		},
		RateLimitConfig: RateLimitConfig{
			Enabled:        true,
			RequestsPerSec: 100,
			Burst:          200,
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// IsActive checks if the tenant is in an active state.
func (t *Tenant) IsActive() bool {
	return t.Status == "active"
}

// GetAccessTokenTTL returns the configured access token TTL.
func (t *Tenant) GetAccessTokenTTL() time.Duration {
	if t.AccessTokenTTL <= 0 {
		return 15 * time.Minute // Default value
	}
	return t.AccessTokenTTL
}

// GetRefreshTokenTTL returns the configured refresh token TTL.
func (t *Tenant) GetRefreshTokenTTL() time.Duration {
	if t.RefreshTokenTTL <= 0 {
		return 30 * 24 * time.Hour // Default value
	}
	return t.RefreshTokenTTL
}

// GetRateLimitThreshold returns the rate limit threshold for the tenant.
func (t *Tenant) GetRateLimitThreshold() (int, int) {
	if !t.RateLimitConfig.Enabled {
		return 0, 0 // Rate limiting disabled
	}
	return t.RateLimitConfig.RequestsPerSec, t.RateLimitConfig.Burst
}

//Personal.AI order the ending
