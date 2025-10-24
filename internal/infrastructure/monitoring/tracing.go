package monitoring

import (
	"context"

	"github.com/turtacn/cbc/internal/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
	"go.opentelemetry.io/otel/trace"
)

// Tracer is a global tracer instance.
var Tracer trace.Tracer

// InitTracer initializes the OpenTelemetry tracer.
func InitTracer(cfg *config.TracingConfig) (func(), error) {
	if !cfg.Enabled {
		// Return a no-op tracer provider if tracing is disabled
		Tracer = otel.GetTracerProvider().Tracer(cfg.ServiceName)
		return func() {}, nil
	}

	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.JaegerEndpoint)))
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(cfg.ServiceName),
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	Tracer = tp.Tracer(cfg.ServiceName)

	cleanup := func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			// handle error
		}
	}
	return cleanup, nil
}

// StartSpan starts a new span from the context.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer.Start(ctx, name, opts...)
}
//Personal.AI order the ending