package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ObservabilityMiddleware returns a Gin middleware that integrates Prometheus metrics and OpenTelemetry tracing.
// For each HTTP request, it starts a new trace span and records metrics for request totals and duration.
// The metrics are labeled with the HTTP method, request path (template), and status code for detailed monitoring.
// ObservabilityMiddleware 返回一个集成了 Prometheus 指标和 OpenTelemetry 跟踪的 Gin 中间件。
// 对于每个 HTTP 请求，它会启动一个新的跟踪范围并记录请求总数和持续时间的指标。
// 指标使用 HTTP 方法、请求路径（模板）和状态代码进行标记，以进行详细监控。
func ObservabilityMiddleware(
	tracer trace.Tracer,
	httpRequestsTotal *prometheus.CounterVec,
	httpRequestDuration *prometheus.HistogramVec,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// Start a new OpenTelemetry trace span for the request.
		// The span name is formatted as "METHOD /path/template".
		ctx, span := tracer.Start(c.Request.Context(), c.Request.Method+" "+c.FullPath())
		defer span.End()

		// Inject the updated context with the new span into the request.
		c.Request = c.Request.WithContext(ctx)

		// Process the request through the rest of the middleware chain and the handler.
		c.Next()

		// After the handler has finished, record metrics.
		duration := time.Since(start)
		status := strconv.Itoa(c.Writer.Status())
		// Use c.FullPath() to get the route template (e.g., "/users/:id") for low-cardinality metric labels.
		path := c.FullPath()
		if path == "" {
			path = "not_found" // Handle cases where no route matches.
		}

		// Increment the total requests counter.
		httpRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		// Observe the request duration histogram.
		httpRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration.Seconds())

		// Add final attributes to the trace span.
		span.SetAttributes(
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.path", path),
			attribute.Int("http.status_code", c.Writer.Status()),
			attribute.String("http.client_ip", c.ClientIP()),
		)
	}
}
