// Package monitoring provides adapters to connect the domain's metrics interface with a concrete implementation like Prometheus.
package monitoring

import (
	"time"

	"github.com/turtacn/cbc/internal/domain/service"
)

// MetricsAdapter implements the domain's service.Metrics interface, sending metrics to a Prometheus backend.
// This adapter translates the domain-specific metric calls into the appropriate Prometheus client calls.
// MetricsAdapter 实现了域的 service.Metrics 接口，将指标发送到 Prometheus 后端。
// 此适配器将特定于域的指标调用转换为适当的 Prometheus 客户端调用。
type MetricsAdapter struct {
	metrics *Metrics
}

// NewMetricsAdapter creates a new adapter that wraps a concrete Prometheus Metrics object,
// satisfying the domain's Metrics interface.
// NewMetricsAdapter 创建一个包装具体 Prometheus Metrics 对象的新适配器，
// 满足域的 Metrics 接口。
func NewMetricsAdapter(metrics *Metrics) service.Metrics {
	return &MetricsAdapter{metrics: metrics}
}

// RecordTokenIssue delegates the call to the underlying Prometheus Metrics object.
// RecordTokenIssue 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordTokenIssue(tenantID, grantType string, success bool, duration time.Duration, errorCode string) {
	a.metrics.RecordTokenIssue(tenantID, grantType, success, duration, errorCode)
}

// RecordTokenIssueByTrust delegates the call to the underlying Prometheus Metrics object.
// RecordTokenIssueByTrust 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordTokenIssueByTrust(trustLevel, tenantID string) {
	a.metrics.RecordTokenIssueByTrust(trustLevel, tenantID)
}

// RecordTokenVerify delegates the call to the underlying Prometheus Metrics object.
// RecordTokenVerify 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordTokenVerify(tenantID string, success bool, errorCode string) {
	a.metrics.RecordTokenVerify(tenantID, success, errorCode)
}

// RecordTokenRevoke delegates the call to the underlying Prometheus Metrics object.
// RecordTokenRevoke 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordTokenRevoke(tenantID, reason string) {
	a.metrics.RecordTokenRevoke(tenantID, reason)
}

// RecordDeviceRegister delegates the call to the underlying Prometheus Metrics object.
// RecordDeviceRegister 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordDeviceRegister(tenantID string, success bool, errorCode string) {
	a.metrics.RecordDeviceRegister(tenantID, success, errorCode)
}

// RecordRateLimitHit delegates the call to the underlying Prometheus Metrics object.
// RecordRateLimitHit 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordRateLimitHit(tenantID, scope string) {
	a.metrics.RecordRateLimitHit(tenantID, scope)
}

// RecordCacheAccess delegates the call to the underlying Prometheus Metrics object.
// RecordCacheAccess 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordCacheAccess(cacheType string, hit bool) {
	a.metrics.RecordCacheAccess(cacheType, hit)
}

// RecordDBQuery delegates the call to the underlying Prometheus Metrics object.
// RecordDBQuery 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordDBQuery(operation string, duration time.Duration) {
	a.metrics.RecordDBQuery(operation, duration)
}

// UpdateDBConnections delegates the call to the underlying Prometheus Metrics object.
// UpdateDBConnections 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) UpdateDBConnections(active, idle int) {
	a.metrics.UpdateDBConnections(active, idle)
}

// RecordVaultAPI delegates the call to the underlying Prometheus Metrics object.
// RecordVaultAPI 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) RecordVaultAPI(operation string, duration time.Duration, err error) {
	a.metrics.RecordVaultAPI(operation, duration, err)
}

// UpdateGoroutineCount delegates the call to the underlying Prometheus Metrics object.
// UpdateGoroutineCount 将调用委托给底层的 Prometheus Metrics 对象。
func (a *MetricsAdapter) UpdateGoroutineCount(count int) {
	a.metrics.UpdateGoroutineCount(count)
}
