package service

import "context"

// StubCDNCacheManager is a no-op implementation of the CDNCacheManager interface.
// It is used in environments where a CDN is not present, such as local development or testing.
// StubCDNCacheManager 是 CDNCacheManager 接口的无操作实现。
// 它用于不存在 CDN 的环境，例如本地开发或测试。
type StubCDNCacheManager struct{}

// PurgeTenantJWKS is a no-op for the stub implementation. It logs the action and returns nil.
// PurgeTenantJWKS 是存根实现的无操作。它记录操作并返回 nil。
func (s *StubCDNCacheManager) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	// In a real stub, you might add logging here to indicate the method was called.
	return nil
}

// PurgePath is a no-op for the stub implementation. It logs the action and returns nil.
// PurgePath 是存根实现的无操作。它记录操作并返回 nil。
func (s *StubCDNCacheManager) PurgePath(ctx context.Context, path string) error {
	// In a real stub, you might add logging here to indicate the method was called.
	return nil
}
