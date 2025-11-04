package fakes

import (
	"context"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/service"
)

// FakeKMS is a mock implementation of domain.CryptoService for testing purposes.
type FakeKMS struct {
	mu        sync.RWMutex
	keys      map[string]map[string]*rsa.PrivateKey // tenant -> kid -> key
	activeKID map[string]string                     // tenant -> active kid
}

// NewFakeKMS creates a new FakeKMS.
func NewFakeKMS() *FakeKMS {
	return &FakeKMS{
		keys:      make(map[string]map[string]*rsa.PrivateKey),
		activeKID: make(map[string]string),
	}
}

// PutKey adds a key to the FakeKMS.
func (f *FakeKMS) PutKey(tenant, kid string, key *rsa.PrivateKey, setActive bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keys[tenant] == nil {
		f.keys[tenant] = make(map[string]*rsa.PrivateKey)
	}
	f.keys[tenant][kid] = key
	if setActive {
		f.activeKID[tenant] = kid
	}
}

// GetPrivateKey retrieves the private key for a given tenant.
func (f *FakeKMS) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	kid, ok := f.activeKID[tenantID]
	if !ok {
		return nil, "", fmt.Errorf("no active kid for tenant %s", tenantID)
	}
	key, ok := f.keys[tenantID][kid]
	if !ok {
		return nil, "", fmt.Errorf("key not found for kid %s", kid)
	}
	return key, kid, nil
}

// GetPublicKey retrieves the public key for a given tenant and key ID.
func (f *FakeKMS) GetPublicKey(ctx context.Context, tenantID, kid string) (*rsa.PublicKey, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	key, ok := f.keys[tenantID][kid]
	if !ok {
		return nil, fmt.Errorf("key not found for kid %s", kid)
	}
	return &key.PublicKey, nil
}

// EncryptSensitiveData is a placeholder implementation.
func (f *FakeKMS) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return data, nil
}

// DecryptSensitiveData is a placeholder implementation.
func (f *FakeKMS) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return data, nil
}

func (f *FakeKMS) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (tokenString string, keyID string, err error) {
	return "", "", nil
}

func (f *FakeKMS) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	return nil, nil
}

func (f *FakeKMS) RotateKey(ctx context.Context, tenantID string) (string, error) {
	return "", nil
}

var _ service.CryptoService = (*FakeKMS)(nil)
