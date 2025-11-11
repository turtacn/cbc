package handlers

import (
	"net/http"
	"time"

	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

type MetricsAdapter struct {
	m *monitoring.Metrics
}

func NewMetricsAdapter(m *monitoring.Metrics) *MetricsAdapter {
	return &MetricsAdapter{m: m}
}

func (a *MetricsAdapter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.m == nil {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		// Increment active requests
		a.m.ActiveRequestsInc(r.URL.Path, r.Method)

		defer func() {
			// Decrement active requests
			a.m.ActiveRequestsDec(r.URL.Path, r.Method)

			// Observe latency
			secs := time.Since(start).Seconds()
			a.m.ObserveRequestDuration(r.URL.Path, r.Method, sw.status, secs)

			// Count errors
			if sw.status >= 400 {
				a.m.IncRequestErrors(r.URL.Path, r.Method, sw.status)
			}
		}()

		next.ServeHTTP(sw, r)
	})
}
