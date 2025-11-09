package models

import (
	"crypto/rsa"
	"time"
)

// Key represents the metadata of a cryptographic key.
type Key struct {
	ID           string `gorm:"primaryKey"`
	TenantID     string
	ProviderType string
	ProviderRef  string
	PublicKey    *rsa.PublicKey `gorm:"-"`
	PublicKeyPEM string
	Status       string
	CompromisedAt *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// KeySpec defines the specifications for a new cryptographic key.
type KeySpec struct {
	// Algorithm is the cryptographic algorithm to use (e.g., "RSA", "ECDSA").
	Algorithm string
	// Bits is the key size in bits (e.g., 2048 for RSA).
	Bits int
}
