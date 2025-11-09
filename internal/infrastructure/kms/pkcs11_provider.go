// Package kms provides KeyProvider implementations.
package kms

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/miekg/pkcs11"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// PKCS11Provider is a PKCS#11-backed implementation of the KeyProvider interface.
type PKCS11Provider struct {
	p          *pkcs11.Ctx
	session    pkcs11.SessionHandle
	logger     logger.Logger
}

// NewPKCS11Provider creates a new PKCS11Provider.
func NewPKCS11Provider(libPath, pin string, slotID int, logger logger.Logger) (service.KeyProvider, error) {
	p := pkcs11.New(libPath)
	if err := p.Initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#11 library: %w", err)
	}

	slots, err := p.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}
	if slotID >= len(slots) {
		return nil, fmt.Errorf("slot ID %d is out of range", slotID)
	}

	session, err := p.OpenSession(slots[slotID], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session: %w", err)
	}

	if err := p.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	return &PKCS11Provider{
		p:       p,
		session: session,
		logger:  logger.WithComponent("PKCS11Provider"),
	}, nil
}

// GenerateKey generates a new key pair in the HSM.
func (p *PKCS11Provider) GenerateKey(ctx context.Context, keySpec models.KeySpec) (string, string, *rsa.PublicKey, error) {
	// Not implemented for this phase.
	return "", "", nil, fmt.Errorf("not implemented")
}

// Sign signs a digest using a private key in the HSM.
func (p *PKCS11Provider) Sign(ctx context.Context, providerRef string, digest []byte) ([]byte, error) {
	// Not implemented for this phase.
	return nil, fmt.Errorf("not implemented")
}

// GetPublicKey retrieves a public key from the HSM.
func (p *PKCS11Provider) GetPublicKey(ctx context.Context, providerRef string) (*rsa.PublicKey, error) {
	// Not implemented for this phase.
	return nil, fmt.Errorf("not implemented")
}

// Backup is not supported for HSMs as keys are non-exportable.
func (p *PKCS11Provider) Backup(ctx context.Context, providerRef string) ([]byte, error) {
	return nil, fmt.Errorf("key backup is not supported for PKCS#11 provider")
}

// Restore is not supported for HSMs.
func (p *PKCS11Provider) Restore(ctx context.Context, encryptedBlob []byte) (string, error) {
	return "", fmt.Errorf("key restore is not supported for PKCS#11 provider")
}
