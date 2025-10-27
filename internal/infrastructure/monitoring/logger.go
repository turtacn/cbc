// Package monitoring 提供日志、指标和追踪的基础设施实现
package monitoring

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/logger"
)

// zapLogger 是 Logger 接口的 Zap 实现
type zapLogger struct {
	logger *zap.Logger
	sugar  *zap.SugaredLogger
	level  zap.AtomicLevel
}

// NewLogger 创建并初始化日志实例
func NewLogger(cfg *config.Config) (logger.Logger, error) {
	// 构建日志编码器配置
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// 解析日志级别
	level := parseLogLevel(cfg.Log.Level)
	atomicLevel := zap.NewAtomicLevelAt(level)

	// 构建核心配置
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.NewMultiWriteSyncer(getWriteSyncers(cfg.Log.OutputPath)...),
		atomicLevel,
	)

	// 创建 logger
	zLog := zap.New(
		core,
		zap.AddCaller(),
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	return &zapLogger{
		logger: zLog,
		sugar:  zLog.Sugar(),
		level:  atomicLevel,
	}, nil
}

// parseLogLevel 解析日志级别字符串
func parseLogLevel(levelStr string) zapcore.Level {
	switch levelStr {
	case "DEBUG", "debug":
		return zapcore.DebugLevel
	case "INFO", "info":
		return zapcore.InfoLevel
	case "WARN", "warn":
		return zapcore.WarnLevel
	case "ERROR", "error":
		return zapcore.ErrorLevel
	case "FATAL", "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// getWriteSyncers 获取日志输出目标
func getWriteSyncers(outputs []string) []zapcore.WriteSyncer {
	syncers := make([]zapcore.WriteSyncer, 0, len(outputs))
	for _, output := range outputs {
		switch output {
		case "stdout":
			syncers = append(syncers, zapcore.AddSync(os.Stdout))
		case "stderr":
			syncers = append(syncers, zapcore.AddSync(os.Stderr))
		default:
			// 文件输出
			if file, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
				syncers = append(syncers, zapcore.AddSync(file))
			}
		}
	}
	if len(syncers) == 0 {
		syncers = append(syncers, zapcore.AddSync(os.Stdout))
	}
	return syncers
}

// Debug 记录调试级别日志
func (l *zapLogger) Debug(ctx context.Context, msg string, fields ...logger.Field) {
	l.logger.Debug(msg, convertFields(fields)...)
}

// Info 记录信息级别日志
func (l *zapLogger) Info(ctx context.Context, msg string, fields ...logger.Field) {
	l.logger.Info(msg, convertFields(fields)...)
}

// Warn 记录警告级别日志
func (l *zapLogger) Warn(ctx context.Context, msg string, fields ...logger.Field) {
	l.logger.Warn(msg, convertFields(fields)...)
}

// Error 记录错误级别日志
func (l *zapLogger) Error(ctx context.Context, msg string, err error, fields ...logger.Field) {
	allFields := append(fields, logger.Field{Key: "error", Value: err})
	l.logger.Error(msg, convertFields(allFields)...)
}

// Fatal 记录致命错误日志并终止程序
func (l *zapLogger) Fatal(ctx context.Context, msg string, err error, fields ...logger.Field) {
	allFields := append(fields, logger.Field{Key: "error", Value: err})
	l.logger.Fatal(msg, convertFields(allFields)...)
}

// WithFields 创建带有预设字段的日志记录器
func (l *zapLogger) WithFields(fields ...logger.Field) logger.Logger {
	return &zapLogger{
		logger: l.logger.With(convertFields(fields)...),
		sugar:  l.sugar.With(convertFieldsToInterfaces(fields)...),
		level:  l.level,
	}
}

// WithComponent creates a new logger for a specific component
func (l *zapLogger) WithComponent(component string) logger.Logger {
	return l.WithFields(logger.String("component", component))
}

// SetLevel sets the logging level
func (l *zapLogger) SetLevel(level constants.LogLevel) {
	l.level.SetLevel(parseLogLevel(string(level)))
}

// GetLevel returns the current logging level
func (l *zapLogger) GetLevel() constants.LogLevel {
	switch l.level.Level() {
	case zapcore.DebugLevel:
		return constants.LogLevelDebug
	case zapcore.InfoLevel:
		return constants.LogLevelInfo
	case zapcore.WarnLevel:
		return constants.LogLevelWarn
	case zapcore.ErrorLevel:
		return constants.LogLevelError
	case zapcore.FatalLevel:
		return constants.LogLevelFatal
	default:
		return constants.LogLevelInfo
	}
}

// Sync 刷新日志缓冲区
func (l *zapLogger) Sync() error {
	return l.logger.Sync()
}

// convertFields 将通用 Field 转换为 Zap Field
func convertFields(fields []logger.Field) []zap.Field {
	zapFields := make([]zap.Field, len(fields))
	for i, f := range fields {
		zapFields[i] = convertField(f)
	}
	return zapFields
}

// convertField 将单个 Field 转换为 Zap Field
func convertField(f logger.Field) zap.Field {
	switch v := f.Value.(type) {
	case string:
		return zap.String(f.Key, v)
	case int:
		return zap.Int(f.Key, v)
	case int64:
		return zap.Int64(f.Key, v)
	case float64:
		return zap.Float64(f.Key, v)
	case bool:
		return zap.Bool(f.Key, v)
	case time.Duration:
		return zap.Duration(f.Key, v)
	case time.Time:
		return zap.Time(f.Key, v)
	case error:
		return zap.Error(v)
	default:
		return zap.Any(f.Key, v)
	}
}

// convertFieldsToInterfaces 将 Field 数组转换为 interface{} 数组
func convertFieldsToInterfaces(fields []logger.Field) []interface{} {
	result := make([]interface{}, 0, len(fields)*2)
	for _, f := range fields {
		result = append(result, f.Key, f.Value)
	}
	return result
}

// extractContextFields 从 Context 中提取日志字段
func extractContextFields(ctx context.Context) []logger.Field {
	fields := make([]logger.Field, 0, 4)

	// 提取 trace_id
	if traceID, ok := ctx.Value("trace_id").(string); ok {
		fields = append(fields, logger.Field{Key: "trace_id", Value: traceID})
	}

	// 提取 span_id
	if spanID, ok := ctx.Value("span_id").(string); ok {
		fields = append(fields, logger.Field{Key: "span_id", Value: spanID})
	}

	// 提取 request_id
	if requestID, ok := ctx.Value("request_id").(string); ok {
		fields = append(fields, logger.Field{Key: "request_id", Value: requestID})
	}

	// 提取 tenant_id
	if tenantID, ok := ctx.Value("tenant_id").(string); ok {
		fields = append(fields, logger.Field{Key: "tenant_id", Value: tenantID})
	}

	return fields
}

// LoggerWithService 为特定服务创建日志记录器
func LoggerWithService(baseLogger logger.Logger, serviceName string) logger.Logger {
	return baseLogger.WithFields(logger.Field{Key: "service", Value: serviceName})
}

// LoggerWithComponent 为特定组件创建日志记录器
func LoggerWithComponent(baseLogger logger.Logger, componentName string) logger.Logger {
	return baseLogger.WithFields(logger.Field{Key: "component", Value: componentName})
}

// LogOperation 记录操作日志的辅助函数
func LogOperation(log logger.Logger, operation string, duration time.Duration, err error, fields ...logger.Field) {
	allFields := append(fields,
		logger.Field{Key: "operation", Value: operation},
		logger.Field{Key: "duration_ms", Value: duration.Milliseconds()},
	)

	if err != nil {
		allFields = append(allFields, logger.Field{Key: "error", Value: err.Error()})
		log.Error(context.Background(), fmt.Sprintf("operation %s failed", operation), err, allFields...)
	} else {
		log.Info(context.Background(), fmt.Sprintf("operation %s completed", operation), allFields...)
	}
}
