// Package models defines the domain models for the CBC authentication service.
// This file contains the Token domain model with business logic.
package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/pkg/constants"
)

// Token represents a JWT token in the authentication system.
// It contains all the necessary information for token lifecycle management.
type Token struct {
	// JTI is the unique JWT ID that prevents token replay attacks
	JTI string `json:"jti" db:"jti"`

	// TenantID identifies which tenant this token belongs to
	TenantID string `json:"tenant_id" db:"tenant_id"`

	// DeviceID identifies the device that holds this token
	DeviceID string `json:"device_id" db:"device_id"`

	// TokenType indicates whether this is an access_token or refresh_token
	TokenType constants.TokenType `json:"token_type" db:"token_type"`

	// Scope defines the permissions granted by this token
	Scope string `json:"scope" db:"scope"`

	// IssuedAt is the timestamp when the token was created
	IssuedAt time.Time `json:"issued_at" db:"issued_at"`

	// ExpiresAt is the timestamp when the token expires
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`

	// RevokedAt is the timestamp when the token was revoked (null if not revoked)
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`

	// DeviceFingerprint is a hash of device characteristics for additional security
	DeviceFingerprint string `json:"device_fingerprint,omitempty" db:"device_fingerprint"`

	// IPAddress is the IP address from which the token was issued
	IPAddress string `json:"ip_address,omitempty" db:"ip_address"`

	// UserAgent is the user agent string from the device
	UserAgent string `json:"user_agent,omitempty" db:"user_agent"`

	// CreatedAt is the database record creation timestamp
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the database record last update timestamp
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Metadata is a map of additional custom data
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// NewToken creates a new Token instance with the provided parameters.
// It automatically sets IssuedAt, CreatedAt, and UpdatedAt to the current time.
func NewToken(jti, tenantID, deviceID string, tokenType constants.TokenType, scope string, ttl time.Duration) *Token {
	now := time.Now().UTC()
	return &Token{
		JTI:       jti,
		TenantID:  tenantID,
		DeviceID:  deviceID,
		TokenType: tokenType,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// IsExpired checks if the token has expired based on the current time.
// Returns true if the current time is after the ExpiresAt timestamp.
func (t *Token) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}

// IsRevoked checks if the token has been explicitly revoked.
// Returns true if RevokedAt is not nil.
func (t *Token) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsValid checks if the token is valid for use.
// A token is valid if it is not expired and not revoked.
func (t *Token) IsValid() bool {
	return !t.IsExpired() && !t.IsRevoked()
}

// CanRefresh checks if a refresh token can be used to obtain new tokens.
// Refresh tokens can only be refreshed if they are valid and of type RefreshToken.
func (t *Token) CanRefresh() bool {
	return t.TokenType == constants.TokenTypeRefresh && t.IsValid()
}

// Revoke marks the token as revoked at the current time.
// This method should be called when explicitly revoking a token.
func (t *Token) Revoke() {
	now := time.Now().UTC()
	t.RevokedAt = &now
	t.UpdatedAt = now
}

// TimeUntilExpiry returns the duration until the token expires.
// Returns 0 if the token is already expired.
func (t *Token) TimeUntilExpiry() time.Duration {
	if t.IsExpired() {
		return 0
	}
	return time.Until(t.ExpiresAt)
}

// IsAccessToken checks if this token is an access token.
func (t *Token) IsAccessToken() bool {
	return t.TokenType == constants.TokenTypeAccess
}

// IsRefreshToken checks if this token is a refresh token.
func (t *Token) IsRefreshToken() bool {
	return t.TokenType == constants.TokenTypeRefresh
}

// HasScope checks if the token has the specified scope.
// This method performs a simple substring check.
func (t *Token) HasScope(scope string) bool {
	if t.Scope == "" {
		return false
	}
	// Simple implementation - in production, you might want to parse scopes more carefully
	return contains(t.Scope, scope)
}

// GetRemainingLifetime returns the remaining lifetime of the token as a percentage.
// Returns 0 if expired, 100 if just issued.
func (t *Token) GetRemainingLifetime() float64 {
	if t.IsExpired() {
		return 0
	}

	totalLifetime := t.ExpiresAt.Sub(t.IssuedAt).Seconds()
	elapsed := time.Now().UTC().Sub(t.IssuedAt).Seconds()

	if totalLifetime == 0 {
		return 0
	}

	remaining := ((totalLifetime - elapsed) / totalLifetime) * 100
	if remaining < 0 {
		return 0
	}

	return remaining
}

// ShouldRotate checks if a refresh token should be rotated based on policy.
// Returns true if the token has been used for more than 50% of its lifetime.
func (t *Token) ShouldRotate() bool {
	if !t.IsRefreshToken() {
		return false
	}
	return t.GetRemainingLifetime() < 50
}

// ValidateDeviceFingerprint checks if the provided fingerprint matches the token's fingerprint.
// This helps prevent token theft and replay attacks.
func (t *Token) ValidateDeviceFingerprint(fingerprint string) bool {
	if t.DeviceFingerprint == "" {
		return true // No fingerprint validation required
	}
	return t.DeviceFingerprint == fingerprint
}

// ToMap converts the Token to a map for flexible serialization.
func (t *Token) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"jti":         t.JTI,
		"tenant_id":   t.TenantID,
		"device_id":   t.DeviceID,
		"token_type":  string(t.TokenType),
		"scope":       t.Scope,
		"issued_at":   t.IssuedAt.Unix(),
		"expires_at":  t.ExpiresAt.Unix(),
		"created_at":  t.CreatedAt.Unix(),
		"updated_at":  t.UpdatedAt.Unix(),
		"is_expired":  t.IsExpired(),
		"is_revoked":  t.IsRevoked(),
	}

	if t.RevokedAt != nil {
		m["revoked_at"] = t.RevokedAt.Unix()
	}

	if t.DeviceFingerprint != "" {
		m["device_fingerprint"] = t.DeviceFingerprint
	}

	if t.IPAddress != "" {
		m["ip_address"] = t.IPAddress
	}

	if t.UserAgent != "" {
		m["user_agent"] = t.UserAgent
	}

	return m
}

// contains is a helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)+1] == substr+" " ||
			s[len(s)-len(substr)-1:] == " "+substr ||
			len(s) > len(substr)*2 && findInMiddle(s, substr))))
}

// findInMiddle checks if substring exists in the middle of the string with spaces.
func findInMiddle(s, substr string) bool {
	target := " " + substr + " "
	for i := 0; i <= len(s)-len(target); i++ {
		if s[i:i+len(target)] == target {
			return true
		}
	}
	return false
}

// ToClaims converts the Token model to a JWT Claims object.
func (t *Token) ToClaims() jwt.Claims {
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        t.JTI,
			Subject:   t.DeviceID, // Or user ID, depending on the grant
			Audience:  jwt.ClaimStrings{"api"},
			ExpiresAt: jwt.NewNumericDate(t.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(t.IssuedAt),
			NotBefore: jwt.NewNumericDate(t.IssuedAt),
		},
		TenantID: t.TenantID,
		DeviceID: t.DeviceID,
		Scope:    t.Scope,
	}
}

// TokenIntrospection represents the response from a token introspection endpoint.
type TokenIntrospection struct {
	Active    bool                   `json:"active"`
	Scope     string                 `json:"scope,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	Username  string                 `json:"username,omitempty"`
	TokenType string                 `json:"token_type,omitempty"`
	Exp       int64                  `json:"exp,omitempty"`
	Iat       int64                  `json:"iat,omitempty"`
	Nbf       int64                  `json:"nbf,omitempty"`
	Sub       string                 `json:"sub,omitempty"`
	Aud       []string               `json:"aud,omitempty"`
	Iss       string                 `json:"iss,omitempty"`
	Jti       string                 `json:"jti,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

//Personal.AI order the ending
