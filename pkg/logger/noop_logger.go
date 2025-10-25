package logger

import "context"

type noopLogger struct{}

// NewNoopLogger creates a new no-op logger.
func NewNoopLogger() Logger {
	return &noopLogger{}
}

func (l *noopLogger) Debug(ctx context.Context, msg string, fields ...Fields) {}
func (l *noopLogger) Info(ctx context.Context, msg string, fields ...Fields)  {}
func (l *noopLogger) Warn(ctx context.Context, msg string, fields ...Fields)  {}
func (l *noopLogger) Error(ctx context.Context, msg string, err error, fields ...Fields) {}
func (l *noopLogger) Fatal(ctx context.Context, msg string, err error, fields ...Fields) {}
func (l *noopLogger) WithFields(fields Fields) Logger {
	return l
}
func (l *noopLogger) ForContext(ctx context.Context) Logger {
	return l
}
