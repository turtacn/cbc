package models

import "github.com/golang-jwt/jwt/v5"

// Claims represents the JWT claims.
type Claims struct {
	jwt.RegisteredClaims
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
	Scope    string `json:"scope"`
}
