// Package monitoring provides the implementation for distributed tracing.
package monitoring

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/logger"
)

// TracingManager manages OpenTelemetry tracing.
type TracingManager struct {
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
	logger   logger.Logger
}

// NewTracingManager creates a new TracingManager.
func NewTracingManager(cfg *config.Config, log logger.Logger) (*TracingManager, error) {
	if !cfg.Observability.Enabled {
		log.Info(context.Background(), "Tracing is disabled")
		return &TracingManager{
			tracer: otel.Tracer("cbc-auth-service"),
			logger: log,
		}, nil
	}

	// Create Jaeger exporter
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(
		jaeger.WithEndpoint(cfg.Observability.OtelEndpoint),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create resource
	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.Observability.ServiceName),
			attribute.String("environment", cfg.Observability.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create TracerProvider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.Observability.SamplingRate)),
	)

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Info(context.Background(), "Tracing initialized successfully",
		logger.String("endpoint", cfg.Observability.OtelEndpoint),
		logger.Float64("sample_rate", cfg.Observability.SamplingRate),
	)

	return &TracingManager{
		tracer:   provider.Tracer("cbc-auth-service"),
		provider: provider,
		logger:   log,
	}, nil
}

// StartSpan starts a new span.
func (tm *TracingManager) StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tm.tracer.Start(ctx, spanName, opts...)
}

// Shutdown gracefully shuts down the tracing provider.
func (tm *TracingManager) Shutdown(ctx context.Context) error {
	if tm.provider == nil {
		return nil
	}
	if err := tm.provider.Shutdown(ctx); err != nil {
		tm.logger.Error(ctx, "Failed to shutdown tracing provider", err)
		return err
	}
	tm.logger.Info(ctx, "Tracing provider shutdown successfully")
	return nil
}
