// Package logger provides structured logging capabilities for the CBC Auth Service.
// It supports multiple log levels, JSON formatting, and integration with OpenTelemetry for distributed tracing.
package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"cbc/pkg/constants"
	"go.opentelemetry.io/otel/trace"
)

// ================================================================================
// Logger Interface
// ================================================================================

// Logger defines the interface for structured logging
type Logger interface {
	// Debug logs a debug message
	Debug(ctx context.Context, message string, fields ...Field)

	// Info logs an informational message
	Info(ctx context.Context, message string, fields ...Field)

	// Warn logs a warning message
	Warn(ctx context.Context, message string, fields ...Field)

	// Error logs an error message
	Error(ctx context.Context, message string, err error, fields ...Field)

	// Fatal logs a fatal message and exits the application
	Fatal(ctx context.Context, message string, err error, fields ...Field)

	// WithFields creates a new logger with additional fields
	WithFields(fields ...Field) Logger

	// WithComponent creates a new logger for a specific component
	WithComponent(component string) Logger

	// SetLevel sets the logging level
	SetLevel(level constants.LogLevel)

	// GetLevel returns the current logging level
	GetLevel() constants.LogLevel
}

// ================================================================================
// Field Type for Structured Logging
// ================================================================================

// Field represents a key-value pair for structured logging
type Field struct {
	Key   string
	Value interface{}
}

// F is a shorthand constructor for Field
func F(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// String creates a string field
func String(key string, value string) Field {
	return Field{Key: key, Value: value}
}

// Int creates an integer field
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Int64 creates an int64 field
func Int64(key string, value int64) Field {
	return Field{Key: key, Value: value}
}

// Float64 creates a float64 field
func Float64(key string, value float64) Field {
	return Field{Key: key, Value: value}
}

// Bool creates a boolean field
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Error creates an error field
func Error(err error) Field {
	if err == nil {
		return Field{Key: "error", Value: nil}
	}
	return Field{Key: "error", Value: err.Error()}
}

// Duration creates a duration field
func Duration(key string, value time.Duration) Field {
	return Field{Key: key, Value: value.String()}
}

// Time creates a time field
func Time(key string, value time.Time) Field {
	return Field{Key: key, Value: value.Format(time.RFC3339)}
}

// Any creates a field with any type
func Any(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

// ================================================================================
// Logger Implementation
// ================================================================================

// logger is the internal implementation of the Logger interface
type logger struct {
	level      constants.LogLevel
	output     io.Writer
	component  string
	baseFields []Field
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Component string                 `json:"component,omitempty"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	TraceID   string                 `json:"trace_id,omitempty"`
	SpanID    string                 `json:"span_id,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
}

// ================================================================================
// Logger Constructor
// ================================================================================

// NewLogger creates a new Logger instance
func NewLogger(level constants.LogLevel, output io.Writer) Logger {
	if output == nil {
		output = os.Stdout
	}

	return &logger{
		level:      level,
		output:     output,
		baseFields: make([]Field, 0),
	}
}

// NewDefaultLogger creates a logger with default settings (stdout, Info level)
func NewDefaultLogger() Logger {
	return NewLogger(constants.LogLevelInfo, os.Stdout)
}

// ================================================================================
// Core Logging Methods
// ================================================================================

// Debug logs a debug message
func (l *logger) Debug(ctx context.Context, message string, fields ...Field) {
	if l.level > constants.LogLevelDebug {
		return
	}
	l.log(ctx, constants.LogLevelDebug, message, nil, fields...)
}

// Info logs an informational message
func (l *logger) Info(ctx context.Context, message string, fields ...Field) {
	if l.level > constants.LogLevelInfo {
		return
	}
	l.log(ctx, constants.LogLevelInfo, message, nil, fields...)
}

// Warn logs a warning message
func (l *logger) Warn(ctx context.Context, message string, fields ...Field) {
	if l.level > constants.LogLevelWarn {
		return
	}
	l.log(ctx, constants.LogLevelWarn, message, nil, fields...)
}

// Error logs an error message
func (l *logger) Error(ctx context.Context, message string, err error, fields ...Field) {
	if l.level > constants.LogLevelError {
		return
	}

	// Append error field if error is not nil
	if err != nil {
		fields = append(fields, Error(err))
	}

	l.log(ctx, constants.LogLevelError, message, err, fields...)
}

// Fatal logs a fatal message and exits
func (l *logger) Fatal(ctx context.Context, message string, err error, fields ...Field) {
	// Always log fatal messages regardless of level
	if err != nil {
		fields = append(fields, Error(err))
	}

	l.log(ctx, constants.LogLevelFatal, message, err, fields...)
	os.Exit(1)
}

// ================================================================================
// Logger Configuration Methods
// ================================================================================

// WithFields creates a new logger with additional base fields
func (l *logger) WithFields(fields ...Field) Logger {
	newLogger := &logger{
		level:      l.level,
		output:     l.output,
		component:  l.component,
		baseFields: make([]Field, len(l.baseFields)+len(fields)),
	}

	copy(newLogger.baseFields, l.baseFields)
	copy(newLogger.baseFields[len(l.baseFields):], fields)

	return newLogger
}

// WithComponent creates a new logger with a component name
func (l *logger) WithComponent(component string) Logger {
	newLogger := &logger{
		level:      l.level,
		output:     l.output,
		component:  component,
		baseFields: make([]Field, len(l.baseFields)),
	}

	copy(newLogger.baseFields, l.baseFields)

	return newLogger
}

// SetLevel sets the logging level
func (l *logger) SetLevel(level constants.LogLevel) {
	l.level = level
}

// GetLevel returns the current logging level
func (l *logger) GetLevel() constants.LogLevel {
	return l.level
}

// ================================================================================
// Internal Logging Implementation
// ================================================================================

// log is the internal method that performs the actual logging
func (l *logger) log(ctx context.Context, level constants.LogLevel, message string, err error, fields ...Field) {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     levelToString(level),
		Component: l.component,
		Message:   message,
		Fields:    make(map[string]interface{}),
	}

	// Extract trace context from OpenTelemetry
	if ctx != nil {
		span := trace.SpanFromContext(ctx)
		if span.SpanContext().IsValid() {
			entry.TraceID = span.SpanContext().TraceID().String()
			entry.SpanID = span.SpanContext().SpanID().String()
		}

		// Extract context values
		if requestID := ctx.Value(constants.ContextKeyRequestID); requestID != nil {
			entry.Fields["request_id"] = requestID
		}
		if tenantID := ctx.Value(constants.ContextKeyTenantID); tenantID != nil {
			entry.Fields["tenant_id"] = tenantID
		}
		if agentID := ctx.Value(constants.ContextKeyAgentID); agentID != nil {
			entry.Fields["agent_id"] = agentID
		}
	}

	// Add caller information for errors and fatal logs
	if level >= constants.LogLevelError {
		entry.Caller = getCaller(3)
	}

	// Merge base fields
	for _, field := range l.baseFields {
		entry.Fields[field.Key] = sanitizeValue(field.Key, field.Value)
	}

	// Merge provided fields
	for _, field := range fields {
		entry.Fields[field.Key] = sanitizeValue(field.Key, field.Value)
	}

	// Marshal to JSON
	jsonData, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		// Fallback to plain text if JSON marshaling fails
		fmt.Fprintf(l.output, "[%s] %s: %s (marshal error: %v)\n",
			entry.Timestamp, entry.Level, message, marshalErr)
		return
	}

	// Write to output
	fmt.Fprintln(l.output, string(jsonData))
}

// ================================================================================
// Utility Functions
// ================================================================================

// levelToString converts a log level to its string representation
func levelToString(level constants.LogLevel) string {
	switch level {
	case constants.LogLevelDebug:
		return "DEBUG"
	case constants.LogLevelInfo:
		return "INFO"
	case constants.LogLevelWarn:
		return "WARN"
	case constants.LogLevelError:
		return "ERROR"
	case constants.LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// getCaller returns the file and line number of the caller
func getCaller(skip int) string {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		return "unknown"
	}

	// Extract just the filename (not the full path)
	parts := strings.Split(file, "/")
	if len(parts) > 0 {
		file = parts[len(parts)-1]
	}

	return fmt.Sprintf("%s:%d", file, line)
}

// sanitizeValue sanitizes sensitive field values
func sanitizeValue(key string, value interface{}) interface{} {
	// List of sensitive field keys that should be masked
	sensitiveKeys := []string{
		"password",
		"secret",
		"token",
		"api_key",
		"authorization",
		"private_key",
		"client_secret",
		"refresh_token",
		"access_token",
	}

	// Check if the key is sensitive
	keyLower := strings.ToLower(key)
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(keyLower, sensitiveKey) {
			// Mask sensitive values
			if str, ok := value.(string); ok && len(str) > 0 {
				return maskString(str)
			}
			return "***REDACTED***"
		}
	}

	return value
}

// maskString partially masks a string value
func maskString(s string) string {
	if len(s) <= 8 {
		return "***"
	}

	// Show first 4 and last 4 characters
	return s[:4] + "***" + s[len(s)-4:]
}

// ================================================================================
// Audit Logging
// ================================================================================

// AuditLogger is a specialized logger for audit events
type AuditLogger struct {
	logger Logger
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger Logger) *AuditLogger {
	return &AuditLogger{
		logger: logger.WithComponent("audit"),
	}
}

// LogAuditEvent logs an audit event
func (a *AuditLogger) LogAuditEvent(ctx context.Context, eventType constants.AuditEventType, fields ...Field) {
	auditFields := append([]Field{
		String("event_type", string(eventType)),
		String("event_category", "audit"),
		Time("event_timestamp", time.Now().UTC()),
	}, fields...)

	a.logger.Info(ctx, "Audit event", auditFields...)
}

// LogTokenIssuance logs a token issuance event
func (a *AuditLogger) LogTokenIssuance(ctx context.Context, tenantID, agentID, clientID string, tokenType constants.TokenType) {
	a.LogAuditEvent(ctx, constants.AuditEventTokenIssued,
		String("tenant_id", tenantID),
		String("agent_id", agentID),
		String("client_id", clientID),
		String("token_type", string(tokenType)),
	)
}

// LogTokenRevocation logs a token revocation event
func (a *AuditLogger) LogTokenRevocation(ctx context.Context, tenantID, jti string, reason string) {
	a.LogAuditEvent(ctx, constants.AuditEventTokenRevoked,
		String("tenant_id", tenantID),
		String("jti", jti),
		String("revocation_reason", reason),
	)
}

// LogAuthenticationFailure logs an authentication failure event
func (a *AuditLogger) LogAuthenticationFailure(ctx context.Context, clientID, reason string) {
	a.LogAuditEvent(ctx, constants.AuditEventAuthenticationFailed,
		String("client_id", clientID),
		String("failure_reason", reason),
	)
}

// LogAuthenticationSuccess logs an authentication success event
func (a *AuditLogger) LogAuthenticationSuccess(ctx context.Context, clientID, tenantID string) {
	a.LogAuditEvent(ctx, constants.AuditEventAuthenticationSuccess,
		String("client_id", clientID),
		String("tenant_id", tenantID),
	)
}

// LogAuthorizationDenied logs an authorization denied event
func (a *AuditLogger) LogAuthorizationDenied(ctx context.Context, tenantID, agentID, reason string) {
	a.LogAuditEvent(ctx, constants.AuditEventAuthorizationDenied,
		String("tenant_id", tenantID),
		String("agent_id", agentID),
		String("denial_reason", reason),
	)
}

// LogKeyRotation logs a key rotation event
func (a *AuditLogger) LogKeyRotation(ctx context.Context, tenantID, oldKeyID, newKeyID string) {
	a.LogAuditEvent(ctx, constants.AuditEventKeyRotated,
		String("tenant_id", tenantID),
		String("old_key_id", oldKeyID),
		String("new_key_id", newKeyID),
	)
}

// LogRateLimitExceeded logs a rate limit exceeded event
func (a *AuditLogger) LogRateLimitExceeded(ctx context.Context, scope string, limit int, clientIP string) {
	a.LogAuditEvent(ctx, constants.AuditEventRateLimitExceeded,
		String("scope", scope),
		Int("limit", limit),
		String("client_ip", clientIP),
	)
}

// LogSuspiciousActivity logs a suspicious activity event
func (a *AuditLogger) LogSuspiciousActivity(ctx context.Context, activityType, description string, metadata map[string]interface{}) {
	fields := []Field{
		String("activity_type", activityType),
		String("description", description),
	}

	for key, value := range metadata {
		fields = append(fields, Any(key, value))
	}

	a.LogAuditEvent(ctx, constants.AuditEventSuspiciousActivity, fields...)
}

// ================================================================================
// Performance Logging
// ================================================================================

// PerformanceLogger tracks operation performance
type PerformanceLogger struct {
	logger Logger
}

// NewPerformanceLogger creates a new performance logger
func NewPerformanceLogger(logger Logger) *PerformanceLogger {
	return &PerformanceLogger{
		logger: logger.WithComponent("performance"),
	}
}

// LogOperationDuration logs the duration of an operation
func (p *PerformanceLogger) LogOperationDuration(ctx context.Context, operation string, duration time.Duration, fields ...Field) {
	perfFields := append([]Field{
		String("operation", operation),
		Duration("duration", duration),
		Int64("duration_ms", duration.Milliseconds()),
	}, fields...)

	// Log as warning if operation is slow
	if duration > 1*time.Second {
		p.logger.Warn(ctx, "Slow operation detected", perfFields...)
	} else {
		p.logger.Debug(ctx, "Operation completed", perfFields...)
	}
}

// StartOperation creates a function to track operation duration
func (p *PerformanceLogger) StartOperation(ctx context.Context, operation string) func(...Field) {
	start := time.Now()

	return func(fields ...Field) {
		duration := time.Since(start)
		p.LogOperationDuration(ctx, operation, duration, fields...)
	}
}

// ================================================================================
// Global Logger Instance
// ================================================================================

var globalLogger Logger = NewDefaultLogger()

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger Logger) {
	globalLogger = logger
}

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() Logger {
	return globalLogger
}

// Debug logs a debug message using the global logger
func Debug(ctx context.Context, message string, fields ...Field) {
	globalLogger.Debug(ctx, message, fields...)
}

// Info logs an info message using the global logger
func Info(ctx context.Context, message string, fields ...Field) {
	globalLogger.Info(ctx, message, fields...)
}

// Warn logs a warning message using the global logger
func Warn(ctx context.Context, message string, fields ...Field) {
	globalLogger.Warn(ctx, message, fields...)
}

// Error logs an error message using the global logger
func Error(ctx context.Context, message string, err error, fields ...Field) {
	globalLogger.Error(ctx, message, err, fields...)
}

// Fatal logs a fatal message using the global logger and exits
func Fatal(ctx context.Context, message string, err error, fields ...Field) {
	globalLogger.Fatal(ctx, message, err, fields...)
}

//Personal.AI order the ending
