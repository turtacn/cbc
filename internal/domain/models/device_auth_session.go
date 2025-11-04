// Package models defines the domain models.
package models

import "time"

// DeviceAuthStatus represents the status of a device authorization request.
type DeviceAuthStatus string

const (
	DeviceAuthStatusPending  DeviceAuthStatus = "pending"
	DeviceAuthStatusApproved DeviceAuthStatus = "approved"
	DeviceAuthStatusDenied   DeviceAuthStatus = "denied"
)

// DeviceAuthSession represents a device authorization session.
type DeviceAuthSession struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scope      string
	Status     DeviceAuthStatus
	ExpiresAt  time.Time
	Interval   int
	LastPollAt time.Time
	TenantID   string
	Subject    string
}
