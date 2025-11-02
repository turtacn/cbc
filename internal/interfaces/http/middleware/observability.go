package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var (
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests.",
		},
		[]string{"method", "path", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "http_request_duration_seconds",
			Help: "Duration of HTTP requests.",
		},
		[]string{"method", "path"},
	)
)

func init() {
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}

// ObservabilityMiddleware creates a middleware for metrics and tracing.
func ObservabilityMiddleware(tracer trace.Tracer) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		ctx, span := tracer.Start(c.Request.Context(), c.Request.Method+" "+c.FullPath())
		defer span.End()

		c.Request = c.Request.WithContext(ctx)

		// Process request
		c.Next()

		// Metrics
		duration := time.Since(start)
		status := strconv.Itoa(c.Writer.Status())
		path := c.FullPath() // Use the route path for low cardinality
		if path == "" {
			path = "not_found"
		}
		httpRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration.Seconds())

		// Tracing attributes
		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", path),
			attribute.Int("http.status_code", c.Writer.Status()),
			attribute.String("http.client_ip", c.ClientIP()),
		)
	}
}
