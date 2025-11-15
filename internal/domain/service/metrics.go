// Package service defines the interfaces for domain services.
package service

import (
	"time"
)

// Metrics defines the interface for collecting business metrics.
// This abstraction allows the application layer to remain independent of the specific monitoring implementation (e.g., Prometheus).
// Metrics 定义了收集业务指标的接口。
// 这种抽象使应用层能够独立于具体的监控实现（例如 Prometheus）。
type Metrics interface {
	// RecordTokenIssue records metrics related to the token issuance process.
	// RecordTokenIssue 记录与令牌颁发过程相关的指标。
	RecordTokenIssue(tenantID, grantType string, success bool, duration time.Duration, errorCode string)

	// RecordTokenIssueByTrust records token issuance events, categorized by the evaluated trust level.
	// RecordTokenIssueByTrust 记录按评估的信任级别分类的令牌颁发事件。
	RecordTokenIssueByTrust(trustLevel, tenantID string)

	// RecordTokenVerify records metrics related to the token verification process.
	// RecordTokenVerify 记录与令牌验证过程相关的指标。
	RecordTokenVerify(tenantID string, success bool, errorCode string)

	// RecordTokenRevoke records an event when a token is revoked.
	// RecordTokenRevoke 记录令牌被吊销的事件。
	RecordTokenRevoke(tenantID, reason string)

	// RecordDeviceRegister records metrics related to the device registration process.
	// RecordDeviceRegister 记录与设备注册过程相关的指标。
	RecordDeviceRegister(tenantID string, success bool, errorCode string)

	// RecordRateLimitHit records an event when a rate limit is triggered.
	// RecordRateLimitHit 记录触发速率限制的事件。
	RecordRateLimitHit(tenantID, scope string)

	// RecordCacheAccess records a cache hit or miss.
	// RecordCacheAccess 记录缓存命中或未命中。
	RecordCacheAccess(cacheType string, hit bool)

	// RecordDBQuery records the duration of a database query.
	// RecordDBQuery 记录数据库查询的持续时间。
	RecordDBQuery(operation string, duration time.Duration)

	// UpdateDBConnections updates the gauge for the current number of database connections.
	// UpdateDBConnections 更新当前数据库连接数的仪表盘。
	UpdateDBConnections(active, idle int)

	// RecordVaultAPI records the latency and error status of a Vault API call.
	// RecordVaultAPI 记录 Vault API 调用的延迟和错误状态。
	RecordVaultAPI(operation string, duration time.Duration, err error)

	// UpdateGoroutineCount updates the gauge for the current number of goroutines.
	// UpdateGoroutineCount 更新当前 goroutine 数量的仪表盘。
	UpdateGoroutineCount(count int)
}
