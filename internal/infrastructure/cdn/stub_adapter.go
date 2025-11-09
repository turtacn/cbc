// Package cdn provides CDN cache management adapters.
package cdn

import (
	"context"
	"fmt"

	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// StubAdapter is a no-op implementation of the CDNCacheManager, for use in development
// or when CDN purging is disabled. It logs the purge requests without taking action.
type StubAdapter struct {
	logger logger.Logger
}

// NewStubAdapter creates a new StubAdapter.
func NewStubAdapter(log logger.Logger) service.CDNCacheManager {
	return &StubAdapter{
		logger: log.WithComponent("StubCDNCacheManager"),
	}
}

// PurgeTenantJWKS logs the request to purge a tenant's JWKS and returns nil.
func (s *StubAdapter) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	path := fmt.Sprintf("/api/v1/auth/jwks/%s", tenantID)
	s.logger.Info(ctx, "CDN Purge STUB", logger.String("path", path))
	return nil
}

// PurgePath logs the request to purge a specific path and returns nil.
func (s *StubAdapter) PurgePath(ctx context.Context, path string) error {
	s.logger.Info(ctx, "CDN Purge STUB", logger.String("path", path))
	return nil
}
