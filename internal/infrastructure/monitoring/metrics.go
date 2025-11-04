// Package monitoring 提供监控指标的实现
package monitoring

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/turtacn/cbc/pkg/constants"
)

// Metrics 定义所有业务指标
type Metrics struct {
	reg prometheus.Registerer
	// Token 相关指标
	TokenIssueRequests   *prometheus.CounterVec
	TokenIssueSuccess    *prometheus.CounterVec
	TokenIssueFailure    *prometheus.CounterVec
	TokenIssueLatency    *prometheus.HistogramVec
	TokenVerifyRequests  *prometheus.CounterVec
	TokenVerifySuccess   *prometheus.CounterVec
	TokenVerifyFailure   *prometheus.CounterVec
	TokenRevokeTotal     *prometheus.CounterVec

	// Device 相关指标
	DeviceRegisterRequests *prometheus.CounterVec
	DeviceRegisterSuccess  *prometheus.CounterVec
	DeviceRegisterFailure  *prometheus.CounterVec

	// Rate Limit 相关指标
	RateLimitHits *prometheus.CounterVec

	// Cache 相关指标
	CacheHits   *prometheus.CounterVec
	CacheMisses *prometheus.CounterVec

	// Database 相关指标
	DBQueryDuration *prometheus.HistogramVec
	DBConnections   *prometheus.GaugeVec

	// Vault 相关指标
	VaultAPILatency *prometheus.HistogramVec
	VaultAPIErrors  *prometheus.CounterVec

	// System 相关指标
	GoroutineCount prometheus.Gauge

	// HTTP metrics
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
}

// NewMetrics 创建并注册所有指标
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	factory := promauto.With(reg)
	metrics := &Metrics{
		reg: reg,
		// Token 指标
		TokenIssueRequests: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_token_issue_requests_total",
				Help: "Total number of token issue requests",
			},
			[]string{"tenant_id", "grant_type"},
		),

		TokenIssueSuccess: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_token_issue_success_total",
				Help: "Total number of successful token issues",
			},
			[]string{"tenant_id", "grant_type"},
		),

		TokenIssueFailure: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_token_issue_failure_total",
				Help: "Total number of failed token issues",
			},
			[]string{"tenant_id", "grant_type", "error_code"},
		),

		TokenIssueLatency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "cbc_auth_token_issue_latency_seconds",
				Help:    "Latency distribution of token issuance",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
			},
			[]string{"tenant_id"},
		),

		TokenVerifyRequests: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_token_verify_requests_total",
				Help: "Total number of token verification requests",
			},
			[]string{"tenant_id"},
		),

		TokenVerifySuccess: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_token_verify_success_total",
				Help: "Total number of successful token verifications",
			},
			[]string{"tenant_id"},
		),

		TokenVerifyFailure: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_token_verify_failure_total",
				Help: "Total number of failed token verifications",
			},
			[]string{"tenant_id", "error_code"},
		),

		TokenRevokeTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_token_revoke_total",
				Help: "Total number of token revocations",
			},
			[]string{"tenant_id", "reason"},
		),

		// Device 指标
		DeviceRegisterRequests: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_device_register_requests_total",
				Help: "Total number of device registration requests",
			},
			[]string{"tenant_id"},
		),

		DeviceRegisterSuccess: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_device_register_success_total",
				Help: "Total number of successful device registrations",
			},
			[]string{"tenant_id"},
		),

		DeviceRegisterFailure: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_device_register_failure_total",
				Help: "Total number of failed device registrations",
			},
			[]string{"tenant_id", "error_code"},
		),

		// Rate Limit 指标
		RateLimitHits: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_rate_limit_hits_total",
				Help: "Total number of rate limit hits",
			},
			[]string{"tenant_id", "scope"},
		),

		// Cache 指标
		CacheHits: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_cache_hits_total",
				Help: "Total number of cache hits",
			},
			[]string{"cache_type"},
		),

		CacheMisses: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_cache_misses_total",
				Help: "Total number of cache misses",
			},
			[]string{"cache_type"},
		),

		// Database 指标
		DBQueryDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "cbc_auth_db_query_duration_seconds",
				Help:    "Database query duration",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
			},
			[]string{"operation"},
		),

		DBConnections: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "cbc_auth_db_connections",
				Help: "Current number of database connections",
			},
			[]string{"state"}, // active, idle
		),

		// Vault 指标
		VaultAPILatency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "cbc_auth_vault_api_latency_seconds",
				Help:    "Vault API call latency",
				Buckets: []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
			},
			[]string{"operation"},
		),

		VaultAPIErrors: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_auth_vault_api_errors_total",
				Help: "Total number of Vault API errors",
			},
			[]string{"operation", "error_type"},
		),

		// System 指标
		GoroutineCount: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "cbc_auth_goroutine_count",
				Help: "Current number of goroutines",
			},
		),

		HTTPRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests.",
			},
			[]string{"method", "path", "status"},
		),

		HTTPRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Duration of HTTP requests.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
	}

	return metrics
}

// RecordTokenIssue 记录 Token 颁发请求
func (m *Metrics) RecordTokenIssue(tenantID, grantType string, success bool, duration time.Duration, errorCode string) {
	m.TokenIssueRequests.WithLabelValues(tenantID, grantType).Inc()

	if success {
		m.TokenIssueSuccess.WithLabelValues(tenantID, grantType).Inc()
	} else {
		m.TokenIssueFailure.WithLabelValues(tenantID, grantType, errorCode).Inc()
	}

	m.TokenIssueLatency.WithLabelValues(tenantID).Observe(duration.Seconds())
}

// RecordTokenVerify 记录 Token 验证请求
func (m *Metrics) RecordTokenVerify(tenantID string, success bool, errorCode string) {
	m.TokenVerifyRequests.WithLabelValues(tenantID).Inc()

	if success {
		m.TokenVerifySuccess.WithLabelValues(tenantID).Inc()
	} else {
		m.TokenVerifyFailure.WithLabelValues(tenantID, errorCode).Inc()
	}
}

// RecordTokenRevoke 记录 Token 吊销
func (m *Metrics) RecordTokenRevoke(tenantID, reason string) {
	m.TokenRevokeTotal.WithLabelValues(tenantID, reason).Inc()
}

// RecordDeviceRegister 记录设备注册请求
func (m *Metrics) RecordDeviceRegister(tenantID string, success bool, errorCode string) {
	m.DeviceRegisterRequests.WithLabelValues(tenantID).Inc()

	if success {
		m.DeviceRegisterSuccess.WithLabelValues(tenantID).Inc()
	} else {
		m.DeviceRegisterFailure.WithLabelValues(tenantID, errorCode).Inc()
	}
}

// RecordRateLimitHit 记录限流触发
func (m *Metrics) RecordRateLimitHit(tenantID, scope string) {
	m.RateLimitHits.WithLabelValues(tenantID, scope).Inc()
}

// RecordCacheAccess 记录缓存访问
func (m *Metrics) RecordCacheAccess(cacheType string, hit bool) {
	if hit {
		m.CacheHits.WithLabelValues(cacheType).Inc()
	} else {
		m.CacheMisses.WithLabelValues(cacheType).Inc()
	}
}

// RecordDBQuery 记录数据库查询
func (m *Metrics) RecordDBQuery(operation string, duration time.Duration) {
	m.DBQueryDuration.WithLabelValues(operation).Observe(duration.Seconds())
}

// UpdateDBConnections 更新数据库连接数
func (m *Metrics) UpdateDBConnections(active, idle int) {
	m.DBConnections.WithLabelValues("active").Set(float64(active))
	m.DBConnections.WithLabelValues("idle").Set(float64(idle))
}

// RecordVaultAPI 记录 Vault API 调用
func (m *Metrics) RecordVaultAPI(operation string, duration time.Duration, err error) {
	m.VaultAPILatency.WithLabelValues(operation).Observe(duration.Seconds())

	if err != nil {
		m.VaultAPIErrors.WithLabelValues(operation, string(constants.ErrorTypeVaultAPI)).Inc()
	}
}

// UpdateGoroutineCount 更新 Goroutine 数量
func (m *Metrics) UpdateGoroutineCount(count int) {
	m.GoroutineCount.Set(float64(count))
}

//Personal.AI order the ending
