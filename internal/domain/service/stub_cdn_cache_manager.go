package service

import "context"

// StubCDNCacheManager is a stub implementation of the CDNCacheManager interface.
type StubCDNCacheManager struct{}

// PurgeTenantJWKS is a no-op for the stub implementation.
func (s *StubCDNCacheManager) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	return nil
}

// PurgePath is a no-op for the stub implementation.
func (s *StubCDNCacheManager) PurgePath(ctx context.Context, path string) error {
	return nil
}
