package monitoring

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/turtacn/cbc/pkg/constants"
)

// Metrics manages the Prometheus metrics.
type Metrics struct {
	TokenIssueRequests *prometheus.CounterVec
	TokenIssueLatency  *prometheus.HistogramVec
	TokenRevocations   *prometheus.CounterVec
	RateLimitHits      *prometheus.CounterVec
}

// NewMetrics creates and registers the Prometheus metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		TokenIssueRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_token_issue_requests_total",
				Help: "Total number of token issue requests.",
			},
			[]string{"tenant_id", "grant_type", "result"},
		),
		TokenIssueLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "cbc_token_issue_latency_seconds",
				Help:    "Latency of token issue requests.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"tenant_id", "grant_type"},
		),
		TokenRevocations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_token_revocations_total",
				Help: "Total number of token revocations.",
			},
			[]string{"tenant_id"},
		),
		RateLimitHits: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cbc_rate_limit_hits_total",
				Help: "Total number of rate limit hits.",
			},
			[]string{"scope"},
		),
	}
}

// RecordTokenIssue records metrics for a token issue event.
func (m *Metrics) RecordTokenIssue(tenantID, grantType, result string, duration time.Duration) {
	m.TokenIssueRequests.WithLabelValues(tenantID, grantType, result).Inc()
	m.TokenIssueLatency.WithLabelValues(tenantID, grantType).Observe(duration.Seconds())
}

// RecordTokenRevocation records metrics for a token revocation event.
func (m *Metrics) RecordTokenRevocation(tenantID string) {
	m.TokenRevocations.WithLabelValues(tenantID).Inc()
}

// RecordRateLimitHit records a rate limit hit.
func (m *Metrics) RecordRateLimitHit(scope constants.RateLimitScope) {
	m.RateLimitHits.WithLabelValues(string(scope)).Inc()
}

//Personal.AI order the ending
