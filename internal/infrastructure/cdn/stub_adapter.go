// Package cdn provides CDN cache management adapters.
package cdn

import (
	"context"
	"fmt"

	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// StubAdapter is a no-op implementation of the CDNCacheManager.
// It is used in environments where a CDN is not present or when purging is disabled.
// It logs the purge requests it receives without performing any actual cache invalidation.
// StubAdapter 是 CDNCacheManager 的一个空操作实现。
// 它用于不存在 CDN 的环境或禁用清除功能时。
// 它会记录收到的清除请求，而不会执行任何实际的缓存失效操作。
type StubAdapter struct {
	logger logger.Logger
}

// NewStubAdapter creates a new StubAdapter instance.
// NewStubAdapter 创建一个新的 StubAdapter 实例。
func NewStubAdapter(log logger.Logger) service.CDNCacheManager {
	return &StubAdapter{
		logger: log.WithComponent("StubCDNCacheManager"),
	}
}

// PurgeTenantJWKS logs that a purge request for a tenant's JWKS was received and returns nil.
// PurgeTenantJWKS 记录收到了一个租户 JWKS 的清除请求，并返回 nil。
func (s *StubAdapter) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	path := fmt.Sprintf("/api/v1/auth/jwks/%s", tenantID)
	s.logger.Info(ctx, "CDN Purge STUB: Received request to purge path", logger.String("path", path))
	return nil
}

// PurgePath logs that a purge request for a specific path was received and returns nil.
// PurgePath 记录收到了一个特定路径的清除请求，并返回 nil。
func (s *StubAdapter) PurgePath(ctx context.Context, path string) error {
	s.logger.Info(ctx, "CDN Purge STUB: Received request to purge path", logger.String("path", path))
	return nil
}
