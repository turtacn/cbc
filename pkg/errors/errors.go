// Package errors defines custom error types and error handling utilities for the CBC Auth Service.
// This package provides structured error types that map to OAuth 2.0 error codes and HTTP status codes.
package errors

import (
	"fmt"
	"net/http"

	"github.com/turtacn/cbc/pkg/constants"
)

// AppError represents a structured application error
type AppError struct {
	Code        string
	Message     string
	Description string
	Details     map[string]string
}

func (e *AppError) Error() string {
	return e.Message
}

var ErrDatabaseOperation = NewError(constants.ErrorCode(ErrCodeInternal), 500, "database operation failed", "database operation failed")

const (
	ErrCodeInternal           = "internal_error"
	ErrCodeInvalidRequest     = "invalid_request"
	ErrCodeUnauthorized       = "unauthorized"
	ErrCodeForbidden          = "forbidden"
	ErrCodeNotFound           = "not_found"
	ErrCodeRateLimitExceeded  = "rate_limit_exceeded"
	ErrCodeServiceUnavailable = "service_unavailable"
	ErrCodeConflict           = "conflict"
	CodeUnauthenticated       = "unauthenticated"
)

// ================================================================================
// Base Error Interface
// ================================================================================

// CBCError represents a structured error with additional metadata
type CBCError interface {
	error

	// Code returns the OAuth 2.0 error code
	Code() constants.ErrorCode

	// HTTPStatus returns the HTTP status code
	HTTPStatus() int

	// Description returns a human-readable description
	Description() string

	// Unwrap returns the underlying error for error chain support
	Unwrap() error

	// WithCause adds a cause error to the error chain
	WithCause(cause error) CBCError

	// WithMetadata adds additional context metadata
	WithMetadata(key string, value interface{}) CBCError

	// Metadata returns all metadata
	Metadata() map[string]interface{}
}

// ================================================================================
// Base Error Implementation
// ================================================================================

// baseError is the internal implementation of CBCError
type baseError struct {
	code        constants.ErrorCode
	httpStatus  int
	description string
	message     string
	cause       error
	metadata    map[string]interface{}
}

// Error implements the error interface
func (e *baseError) Error() string {
	if e.message != "" {
		return e.message
	}
	return e.description
}

// Code returns the OAuth 2.0 error code
func (e *baseError) Code() constants.ErrorCode {
	return e.code
}

// HTTPStatus returns the HTTP status code
func (e *baseError) HTTPStatus() int {
	return e.httpStatus
}

// Description returns the error description
func (e *baseError) Description() string {
	return e.description
}

// Unwrap returns the underlying cause error
func (e *baseError) Unwrap() error {
	return e.cause
}

// WithCause adds a cause error to the error chain
func (e *baseError) WithCause(cause error) CBCError {
	e.cause = cause
	return e
}

// WithMetadata adds additional context metadata
func (e *baseError) WithMetadata(key string, value interface{}) CBCError {
	if e.metadata == nil {
		e.metadata = make(map[string]interface{})
	}
	e.metadata[key] = value
	return e
}

// Metadata returns all metadata
func (e *baseError) Metadata() map[string]interface{} {
	return e.metadata
}

// ================================================================================
// Error Constructor
// ================================================================================

// NewError creates a new CBCError with the specified parameters
func NewError(code constants.ErrorCode, httpStatus int, description string, message string) CBCError {
	return &baseError{
		code:        code,
		httpStatus:  httpStatus,
		description: description,
		message:     message,
		metadata:    make(map[string]interface{}),
	}
}

// ================================================================================
// Predefined Error Constructors
// ================================================================================

// ErrInvalidRequest creates an invalid_request error
func ErrInvalidRequest(message string) CBCError {
	return NewError(
		constants.ErrCodeInvalidRequest,
		http.StatusBadRequest,
		"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.",
		message,
	)
}

// ErrInvalidClient creates an invalid_client error
func ErrInvalidClient(message string) CBCError {
	return NewError(
		constants.ErrCodeInvalidClient,
		http.StatusUnauthorized,
		"Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).",
		message,
	)
}

// ErrInvalidGrant creates an invalid_grant error
func ErrInvalidGrant(message string) CBCError {
	return NewError(
		constants.ErrCodeInvalidGrant,
		http.StatusBadRequest,
		"The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, or does not match the redirection URI.",
		message,
	)
}

// ErrUnauthorizedClient creates an unauthorized_client error
func ErrUnauthorizedClient(message string) CBCError {
	return NewError(
		constants.ErrCodeUnauthorizedClient,
		http.StatusBadRequest,
		"The authenticated client is not authorized to use this authorization grant type.",
		message,
	)
}

// ErrUnsupportedGrantType creates an unsupported_grant_type error
func ErrUnsupportedGrantType(message string) CBCError {
	return NewError(
		constants.ErrCodeUnsupportedGrantType,
		http.StatusBadRequest,
		"The authorization grant type is not supported by the authorization server.",
		message,
	)
}

// ErrInvalidScope creates an invalid_scope error
func ErrInvalidScope(message string) CBCError {
	return NewError(
		constants.ErrCodeInvalidScope,
		http.StatusBadRequest,
		"The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.",
		message,
	)
}

// ErrServerError creates a server_error error
func ErrServerError(message string) CBCError {
	return NewError(
		constants.ErrCodeServerError,
		http.StatusInternalServerError,
		"The authorization server encountered an unexpected condition that prevented it from fulfilling the request.",
		message,
	)
}

// ErrTemporarilyUnavailable creates a temporarily_unavailable error
func ErrTemporarilyUnavailable(message string) CBCError {
	return NewError(
		constants.ErrCodeTemporarilyUnavailable,
		http.StatusServiceUnavailable,
		"The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.",
		message,
	)
}

// ================================================================================
// Domain-Specific Error Constructors
// ================================================================================

// ErrTokenExpired creates a token expired error
func ErrTokenExpired(tokenType string) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("%s token has expired", tokenType)).
		WithMetadata("token_type", tokenType)
}

// ErrTokenRevoked creates a token revoked error
func ErrTokenRevoked(tokenType string, jti string) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("%s token has been revoked", tokenType)).
		WithMetadata("token_type", tokenType).
		WithMetadata("jti", jti)
}

// ErrTokenNotFound creates a token not found error
func ErrTokenNotFound(jti string) CBCError {
	return NewError(
		constants.ErrCodeInvalidGrant,
		http.StatusBadRequest,
		"Token not found",
		fmt.Sprintf("Token with JTI %s not found", jti),
	).WithMetadata("jti", jti)
}

// ErrTokenMalformed creates a token malformed error
func ErrTokenMalformed(reason string) CBCError {
	return ErrInvalidRequest(fmt.Sprintf("Token is malformed: %s", reason)).
		WithMetadata("reason", reason)
}

// ErrTokenSignatureInvalid creates a token signature invalid error
func ErrTokenSignatureInvalid() CBCError {
	return ErrInvalidGrant("Token signature verification failed")
}

// ErrTenantNotFound creates a tenant not found error
func ErrTenantNotFound(tenantID string) CBCError {
	return ErrInvalidClient(fmt.Sprintf("Tenant not found: %s", tenantID)).
		WithMetadata("tenant_id", tenantID)
}

// ErrTenantSuspended creates a tenant suspended error
func ErrTenantSuspended(tenantID string) CBCError {
	return ErrUnauthorizedClient(fmt.Sprintf("Tenant is suspended: %s", tenantID)).
		WithMetadata("tenant_id", tenantID)
}

// ErrMgrClientNotFound creates an MGR client not found error
func ErrMgrClientNotFound(clientID string) CBCError {
	return ErrInvalidClient(fmt.Sprintf("MGR client not found: %s", clientID)).
		WithMetadata("client_id", clientID)
}

// ErrMgrClientAssertionInvalid creates an MGR client assertion invalid error
func ErrMgrClientAssertionInvalid(reason string) CBCError {
	return ErrInvalidClient(fmt.Sprintf("Client assertion is invalid: %s", reason)).
		WithMetadata("reason", reason)
}

// ErrAgentNotFound creates an agent not found error
func ErrAgentNotFound(agentID string) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("Agent not found: %s", agentID)).
		WithMetadata("agent_id", agentID)
}

// ErrDeviceNotFound creates a device not found error
func ErrDeviceNotFound(deviceID string) CBCError {
	return NewError(
		ErrCodeNotFound,
		http.StatusNotFound,
		"Device not found",
		fmt.Sprintf("Device not found: %s", deviceID),
	).WithMetadata("device_id", deviceID)
}

// ErrDeviceUntrusted creates a device untrusted error
func ErrDeviceUntrusted(deviceID string, trustLevel string) CBCError {
	return ErrUnauthorizedClient(fmt.Sprintf("Device trust level insufficient: %s", trustLevel)).
		WithMetadata("device_id", deviceID).
		WithMetadata("trust_level", trustLevel)
}

// ErrRateLimitExceeded creates a rate limit exceeded error
func ErrRateLimitExceeded(scope string, limit int) CBCError {
	return NewError(
		constants.ErrCodeInvalidRequest,
		http.StatusTooManyRequests,
		"Rate limit exceeded. Please try again later.",
		fmt.Sprintf("Rate limit exceeded for scope '%s': %d requests", scope, limit),
	).WithMetadata("scope", scope).
		WithMetadata("limit", limit)
}

// ErrJTIDuplicate creates a JTI duplicate error
func ErrJTIDuplicate(jti string) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("Token with JTI already exists: %s", jti)).
		WithMetadata("jti", jti)
}

// ErrPublicKeyNotFound creates a public key not found error
func ErrPublicKeyNotFound(tenantID string, keyID string) CBCError {
	return ErrServerError(fmt.Sprintf("Public key not found for tenant %s, key %s", tenantID, keyID)).
		WithMetadata("tenant_id", tenantID).
		WithMetadata("key_id", keyID)
}

// ErrPublicKeyRevoked creates a public key revoked error
func ErrPublicKeyRevoked(keyID string) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("Public key has been revoked: %s", keyID)).
		WithMetadata("key_id", keyID)
}

// ErrVaultConnectionFailed creates a Vault connection failed error
func ErrVaultConnectionFailed(reason string) CBCError {
	return ErrServerError(fmt.Sprintf("Failed to connect to Vault: %s", reason)).
		WithMetadata("reason", reason)
}

// ErrDatabaseConnectionFailed creates a database connection failed error
func ErrDatabaseConnectionFailed(reason string) CBCError {
	return ErrServerError(fmt.Sprintf("Failed to connect to database: %s", reason)).
		WithMetadata("reason", reason)
}

// ErrCacheConnectionFailed creates a cache connection failed error
func ErrCacheConnectionFailed(reason string) CBCError {
	return ErrServerError(fmt.Sprintf("Failed to connect to cache: %s", reason)).
		WithMetadata("reason", reason)
}

// ErrKafkaConnectionFailed creates a Kafka connection failed error
func ErrKafkaConnectionFailed(reason string) CBCError {
	return ErrServerError(fmt.Sprintf("Failed to connect to Kafka: %s", reason)).
		WithMetadata("reason", reason)
}

// ErrMissingRequiredParameter creates a missing required parameter error
func ErrMissingRequiredParameter(paramName string) CBCError {
	return ErrInvalidRequest(fmt.Sprintf("Missing required parameter: %s", paramName)).
		WithMetadata("parameter", paramName)
}

// ErrInvalidParameterFormat creates an invalid parameter format error
func ErrInvalidParameterFormat(paramName string, expectedFormat string) CBCError {
	return ErrInvalidRequest(fmt.Sprintf("Invalid format for parameter '%s': expected %s", paramName, expectedFormat)).
		WithMetadata("parameter", paramName).
		WithMetadata("expected_format", expectedFormat)
}

// ErrInvalidAudienceClaim creates an invalid audience claim error
func ErrInvalidAudienceClaim(expected string, actual string) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("Invalid audience claim: expected '%s', got '%s'", expected, actual)).
		WithMetadata("expected", expected).
		WithMetadata("actual", actual)
}

// ErrInvalidIssuerClaim creates an invalid issuer claim error
func ErrInvalidIssuerClaim(expected string, actual string) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("Invalid issuer claim: expected '%s', got '%s'", expected, actual)).
		WithMetadata("expected", expected).
		WithMetadata("actual", actual)
}

// ErrClaimMismatch creates a claim mismatch error
func ErrClaimMismatch(claimName string, expected interface{}, actual interface{}) CBCError {
	return ErrInvalidGrant(fmt.Sprintf("Claim mismatch for '%s': expected '%v', got '%v'", claimName, expected, actual)).
		WithMetadata("claim", claimName).
		WithMetadata("expected", expected).
		WithMetadata("actual", actual)
}

// ================================================================================
// Error Validation Utilities
// ================================================================================

// IsCBCError checks if an error is a CBCError
func IsCBCError(err error) bool {
	_, ok := err.(CBCError)
	return ok
}

// AsCBCError attempts to cast an error to CBCError
func AsCBCError(err error) (CBCError, bool) {
	cbcErr, ok := err.(CBCError)
	return cbcErr, ok
}

// WrapError wraps a generic error into a CBCError
func WrapError(err error, code constants.ErrorCode, message string) CBCError {
	var httpStatus int

	switch code {
	case constants.ErrCodeInvalidRequest, constants.ErrCodeInvalidGrant,
		constants.ErrCodeUnauthorizedClient, constants.ErrCodeUnsupportedGrantType,
		constants.ErrCodeInvalidScope:
		httpStatus = http.StatusBadRequest
	case constants.ErrCodeInvalidClient:
		httpStatus = http.StatusUnauthorized
	case constants.ErrCodeServerError:
		httpStatus = http.StatusInternalServerError
	case constants.ErrCodeTemporarilyUnavailable:
		httpStatus = http.StatusServiceUnavailable
	default:
		httpStatus = http.StatusInternalServerError
	}

	return NewError(code, httpStatus, err.Error(), message).WithCause(err)
}

// ================================================================================
// Error Response Builder
// ================================================================================

// ErrorResponse represents the JSON structure for error responses
type ErrorResponse struct {
	Error            string                 `json:"error"`
	ErrorDescription string                 `json:"error_description"`
	ErrorURI         string                 `json:"error_uri,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// ToErrorResponse converts a CBCError to an ErrorResponse
func ToErrorResponse(err CBCError) *ErrorResponse {
	return &ErrorResponse{
		Error:            string(err.Code()),
		ErrorDescription: err.Description(),
		Metadata:         err.Metadata(),
	}
}

// ToGenericErrorResponse converts any error to an ErrorResponse
func ToGenericErrorResponse(err error) *ErrorResponse {
	if cbcErr, ok := AsCBCError(err); ok {
		return ToErrorResponse(cbcErr)
	}

	// Fallback to generic server error
	return &ErrorResponse{
		Error:            string(constants.ErrCodeServerError),
		ErrorDescription: "An unexpected error occurred",
	}
}

// ================================================================================
// Error Context Builder
// ================================================================================

// ErrorContext provides additional context for errors
type ErrorContext struct {
	RequestID   string
	TenantID    string
	AgentID     string
	ClientIP    string
	UserAgent   string
	Timestamp   string
	TraceID     string
	SpanID      string
}

// EnrichError adds context information to an error
func EnrichError(err CBCError, ctx *ErrorContext) CBCError {
	if ctx == nil {
		return err
	}

	if ctx.RequestID != "" {
		err.WithMetadata("request_id", ctx.RequestID)
	}
	if ctx.TenantID != "" {
		err.WithMetadata("tenant_id", ctx.TenantID)
	}
	if ctx.AgentID != "" {
		err.WithMetadata("agent_id", ctx.AgentID)
	}
	if ctx.ClientIP != "" {
		err.WithMetadata("client_ip", ctx.ClientIP)
	}
	if ctx.UserAgent != "" {
		err.WithMetadata("user_agent", ctx.UserAgent)
	}
	if ctx.Timestamp != "" {
		err.WithMetadata("timestamp", ctx.Timestamp)
	}
	if ctx.TraceID != "" {
		err.WithMetadata("trace_id", ctx.TraceID)
	}
	if ctx.SpanID != "" {
		err.WithMetadata("span_id", ctx.SpanID)
	}

	return err
}

// ================================================================================
// Error Logging Utilities
// ================================================================================

// IsTransientError checks if an error is transient and can be retried
func IsTransientError(err error) bool {
	if cbcErr, ok := AsCBCError(err); ok {
		return cbcErr.Code() == constants.ErrCodeTemporarilyUnavailable
	}
	return false
}

// IsAuthenticationError checks if an error is related to authentication
func IsAuthenticationError(err error) bool {
	if cbcErr, ok := AsCBCError(err); ok {
		code := cbcErr.Code()
		return code == constants.ErrCodeInvalidClient ||
			code == constants.ErrCodeUnauthorizedClient
	}
	return false
}

// IsAuthorizationError checks if an error is related to authorization
func IsAuthorizationError(err error) bool {
	if cbcErr, ok := AsCBCError(err); ok {
		code := cbcErr.Code()
		return code == constants.ErrCodeInvalidScope ||
			code == constants.ErrCodeUnauthorizedClient
	}
	return false
}

// IsRateLimitError checks if an error is related to rate limiting
func IsRateLimitError(err error) bool {
	if cbcErr, ok := AsCBCError(err); ok {
		return cbcErr.HTTPStatus() == http.StatusTooManyRequests
	}
	return false
}

// ShouldLogError determines if an error should be logged based on severity
func ShouldLogError(err error) bool {
	if cbcErr, ok := AsCBCError(err); ok {
		// Don't log client errors (4xx) except rate limiting
		status := cbcErr.HTTPStatus()
		return status >= 500 || status == http.StatusTooManyRequests
	}
	return true
}

// IsNotFoundError checks if an error is a not found error.
func IsNotFoundError(err error) bool {
	if cbcErr, ok := AsCBCError(err); ok {
		return cbcErr.Code() == "not_found"
	}
	return false
}

//Personal.AI order the ending
