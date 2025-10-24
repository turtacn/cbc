package logger

import "context"

// Log fields type
type Fields map[string]interface{}

// Logger defines the interface for logging.
// It supports structured logging and context propagation.
type Logger interface {
	// Debug logs a message at DebugLevel.
	Debug(ctx context.Context, msg string, fields ...Fields)

	// Info logs a message at InfoLevel.
	Info(ctx context.Context, msg string, fields ...Fields)

	// Warn logs a message at WarnLevel.
	Warn(ctx context.Context, msg string, fields ...Fields)

	// Error logs a message at ErrorLevel.
	Error(ctx context.Context, msg string, err error, fields ...Fields)

	// Fatal logs a message at FatalLevel then calls os.Exit(1).
	Fatal(ctx context.Context, msg string, err error, fields ...Fields)

	// WithFields returns a new logger with the given fields.
	// These fields will be added to all subsequent log entries.
	WithFields(fields Fields) Logger

	// ForContext returns a logger from the context, or the default logger if not found.
	ForContext(ctx context.Context) Logger
}
//Personal.AI order the ending