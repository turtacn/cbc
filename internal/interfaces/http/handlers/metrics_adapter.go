package handlers

import (
	"context"
	"time"

	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
)

type HTTPMetrics interface {
	RecordRequestStart(ctx context.Context, route string)
	RecordRequestDuration(ctx context.Context, route string, status int, d time.Duration)
	RecordRequestError(ctx context.Context, route string, status int)
}

type MetricsAdapter struct{ m *monitoring.Metrics }

func NewMetricsAdapter(m *monitoring.Metrics) *MetricsAdapter { return &MetricsAdapter{m: m} }

func (a *MetricsAdapter) RecordRequestStart(ctx context.Context, route string) {
	// map to existing counters/timers in monitoring.Metrics; if nothing similar, leave empty
}

func (a *MetricsAdapter) RecordRequestDuration(ctx context.Context, route string, status int, d time.Duration) {
	// map or leave empty for now
}

func (a *MetricsAdapter) RecordRequestError(ctx context.Context, route string, status int) {
	// map or leave empty for now
}
