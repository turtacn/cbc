package monitoring

import (
	"context"
	"os"

	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/logger"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type zapLogger struct {
	*zap.Logger
}

func NewZapLogger(cfg *config.LogConfig) (logger.Logger, error) {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		level = zapcore.InfoLevel
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)

	return &zapLogger{zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))}, nil
}

func (l *zapLogger) Debug(ctx context.Context, msg string, fields ...logger.Fields) {
	l.Logger.Debug(msg, l.convertFields(ctx, fields...)...)
}

func (l *zapLogger) Info(ctx context.Context, msg string, fields ...logger.Fields) {
	l.Logger.Info(msg, l.convertFields(ctx, fields...)...)
}

func (l *zapLogger) Warn(ctx context.Context, msg string, fields ...logger.Fields) {
	l.Logger.Warn(msg, l.convertFields(ctx, fields...)...)
}

func (l *zapLogger) Error(ctx context.Context, msg string, err error, fields ...logger.Fields) {
	allFields := append(fields, logger.Fields{"error": err})
	l.Logger.Error(msg, l.convertFields(ctx, allFields...)...)
}

func (l *zapLogger) Fatal(ctx context.Context, msg string, err error, fields ...logger.Fields) {
	allFields := append(fields, logger.Fields{"error": err})
	l.Logger.Fatal(msg, l.convertFields(ctx, allFields...)...)
}

func (l *zapLogger) WithFields(fields logger.Fields) logger.Logger {
	return &zapLogger{l.Logger.With(l.convertFields(context.Background(), fields)...)}
}

func (l *zapLogger) ForContext(ctx context.Context) logger.Logger {
	if ctxLogger, ok := ctx.Value(constants.ContextKeyLogger).(logger.Logger); ok {
		return ctxLogger
	}
	return l
}

func (l *zapLogger) convertFields(ctx context.Context, fields ...logger.Fields) []zap.Field {
	zapFields := make([]zap.Field, 0)
	if traceID, ok := ctx.Value(constants.ContextKeyTraceID).(string); ok {
		zapFields = append(zapFields, zap.String("trace_id", traceID))
	}

	for _, f := range fields {
		for k, v := range f {
			zapFields = append(zapFields, zap.Any(k, v))
		}
	}
	return zapFields
}

//Personal.AI order the ending
