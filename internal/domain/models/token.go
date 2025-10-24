package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/pkg/constants"
)

// Token represents the core domain model for an authentication token.
type Token struct {
	ID         uuid.UUID
	JTI        string
	TenantID   uuid.UUID
	DeviceID   uuid.UUID
	TokenType  constants.TokenType
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	Scope      string
	Audience   []string
	Issuer     string
}

// NewToken creates a new token instance.
func NewToken(tenantID, deviceID uuid.UUID, tokenType constants.TokenType, ttl time.Duration, scope string, audience []string, issuer string) *Token {
	now := time.Now().UTC()
	return &Token{
		ID:        uuid.New(),
		JTI:       uuid.NewString(),
		TenantID:  tenantID,
		DeviceID:  deviceID,
		TokenType: tokenType,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		Scope:     scope,
		Audience:  audience,
		Issuer:    issuer,
	}
}

// IsExpired checks if the token has expired.
func (t *Token) IsExpired() bool {
	return t.ExpiresAt.Before(time.Now().UTC())
}

// IsRevoked checks if the token has been revoked.
func (t *Token) IsRevoked() bool {
	return t.RevokedAt != nil && !t.RevokedAt.IsZero()
}

// IsValid checks if the token is neither expired nor revoked.
func (t *Token) IsValid() bool {
	return !t.IsExpired() && !t.IsRevoked()
}

// CanRefresh checks if the token is a valid, non-expired, non-revoked refresh token.
func (t *Token) CanRefresh() bool {
	if t.TokenType != constants.RefreshToken {
		return false
	}
	return t.IsValid()
}

// Revoke marks the token as revoked.
func (t *Token) Revoke() {
	now := time.Now().UTC()
	t.RevokedAt = &now
}
//Personal.AI order the ending