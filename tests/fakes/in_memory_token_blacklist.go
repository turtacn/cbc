package fakes

import (
	"context"
	"sync"
	"time"

	"github.com/turtacn/cbc/internal/domain/service"
)

// InMemoryTokenBlacklist provides an in-memory implementation of the TokenBlacklistStore for testing.
type InMemoryTokenBlacklist struct {
	mu      sync.RWMutex
	storage map[string]time.Time
}

// NewInMemoryTokenBlacklist creates a new instance of InMemoryTokenBlacklist.
func NewInMemoryTokenBlacklist() service.TokenBlacklistStore {
	return &InMemoryTokenBlacklist{
		storage: make(map[string]time.Time),
	}
}

// Revoke adds a JTI to the blacklist with an expiration time.
func (s *InMemoryTokenBlacklist) Revoke(ctx context.Context, tenantID, jti string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clean up expired tokens to prevent memory leak in long-running tests
	for k, expiry := range s.storage {
		if time.Now().After(expiry) {
			delete(s.storage, k)
		}
	}

	key := s.key(tenantID, jti)
	s.storage[key] = exp
	return nil
}

// IsRevoked checks if a JTI is in the blacklist and not expired.
func (s *InMemoryTokenBlacklist) IsRevoked(ctx context.Context, tenantID, jti string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := s.key(tenantID, jti)
	exp, exists := s.storage[key]
	if !exists {
		return false, nil
	}

	if time.Now().After(exp) {
		// It's expired, so it's not considered revoked anymore.
		// We can remove it lazily.
		go func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			delete(s.storage, key)
		}()
		return false, nil
	}

	return true, nil
}

func (s *InMemoryTokenBlacklist) key(tenantID, jti string) string {
	return tenantID + ":" + jti
}
