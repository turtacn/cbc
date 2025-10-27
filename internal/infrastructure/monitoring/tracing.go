// Package monitoring 提供分布式追踪的实现
package monitoring

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/logger"
)

// TracingManager 管理 OpenTelemetry 追踪
type TracingManager struct {
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
	logger   logger.Logger
}

// NewTracingManager 创建追踪管理器
func NewTracingManager(cfg *config.Config, log logger.Logger) (*TracingManager, error) {
	if !cfg.Tracing.Enabled {
		log.Info(context.Background(), "Tracing is disabled")
		return &TracingManager{
			tracer: otel.Tracer("cbc-auth-service"),
			logger: log,
		}, nil
	}

	// 创建 Jaeger exporter
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(
		jaeger.WithEndpoint(cfg.Tracing.JaegerEndpoint),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// 创建资源
	res, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.Tracing.ServiceName),
			attribute.String("environment", cfg.Tracing.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// 创建 TracerProvider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.Tracing.SamplingRate)),
	)

	// 设置全局 TracerProvider
	otel.SetTracerProvider(provider)

	// 设置全局 Propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Info(context.Background(), "Tracing initialized successfully",
		logger.String("endpoint", cfg.Tracing.JaegerEndpoint),
		logger.Float64("sample_rate", cfg.Tracing.SamplingRate),
	)

	return &TracingManager{
		tracer:   provider.Tracer("cbc-auth-service"),
		provider: provider,
		logger:   log,
	}, nil
}

// StartSpan 开始一个新的 Span
func (tm *TracingManager) StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tm.tracer.Start(ctx, spanName, opts...)
}

// StartSpanWithAttributes 开始一个带有属性的 Span
func (tm *TracingManager) StartSpanWithAttributes(ctx context.Context, spanName string, attrs map[string]interface{}) (context.Context, trace.Span) {
	attributes := make([]attribute.KeyValue, 0, len(attrs))
	for key, value := range attrs {
		attributes = append(attributes, convertToAttribute(key, value))
	}

	return tm.tracer.Start(ctx, spanName, trace.WithAttributes(attributes...))
}

// AddEvent 向当前 Span 添加事件
func (tm *TracingManager) AddEvent(ctx context.Context, name string, attrs map[string]interface{}) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	attributes := make([]attribute.KeyValue, 0, len(attrs))
	for key, value := range attrs {
		attributes = append(attributes, convertToAttribute(key, value))
	}

	span.AddEvent(name, trace.WithAttributes(attributes...))
}

// RecordError 记录错误到 Span
func (tm *TracingManager) RecordError(ctx context.Context, err error, attrs map[string]interface{}) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	attributes := make([]attribute.KeyValue, 0, len(attrs))
	for key, value := range attrs {
		attributes = append(attributes, convertToAttribute(key, value))
	}

	span.RecordError(err, trace.WithAttributes(attributes...))
	span.SetStatus(codes.Error, err.Error())
}

// SetSpanStatus 设置 Span 状态
func (tm *TracingManager) SetSpanStatus(ctx context.Context, code codes.Code, description string) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	span.SetStatus(code, description)
}

// SetSpanAttributes 设置 Span 属性
func (tm *TracingManager) SetSpanAttributes(ctx context.Context, attrs map[string]interface{}) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	for key, value := range attrs {
		span.SetAttributes(convertToAttribute(key, value))
	}
}

// GetTraceID 获取当前 Trace ID
func (tm *TracingManager) GetTraceID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().TraceID().String()
}

// GetSpanID 获取当前 Span ID
func (tm *TracingManager) GetSpanID(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return ""
	}
	return span.SpanContext().SpanID().String()
}

// InjectTraceContext 注入追踪上下文到 Carrier
func (tm *TracingManager) InjectTraceContext(ctx context.Context, carrier propagation.TextMapCarrier) {
	otel.GetTextMapPropagator().Inject(ctx, carrier)
}

// ExtractTraceContext 从 Carrier 提取追踪上下文
func (tm *TracingManager) ExtractTraceContext(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}

// Shutdown 关闭追踪管理器
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

// convertToAttribute 将 interface{} 转换为 OpenTelemetry 属性
func convertToAttribute(key string, value interface{}) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case int:
		return attribute.Int(key, v)
	case int64:
		return attribute.Int64(key, v)
	case float64:
		return attribute.Float64(key, v)
	case bool:
		return attribute.Bool(key, v)
	case []string:
		return attribute.StringSlice(key, v)
	case []int:
		return attribute.IntSlice(key, v)
	case []int64:
		return attribute.Int64Slice(key, v)
	case []float64:
		return attribute.Float64Slice(key, v)
	case []bool:
		return attribute.BoolSlice(key, v)
	default:
		return attribute.String(key, fmt.Sprintf("%v", v))
	}
}

// TraceOperation 追踪一个操作的辅助函数
func TraceOperation(ctx context.Context, tm *TracingManager, operationName string, fn func(context.Context) error, attrs map[string]interface{}) error {
	ctx, span := tm.StartSpanWithAttributes(ctx, operationName, attrs)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		tm.RecordError(ctx, err, attrs)
		return err
	}

	tm.SetSpanStatus(ctx, codes.Ok, "operation completed successfully")
	return nil
}

//Personal.AI order the ending
