package errors

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/turtacn/cbc/pkg/constants"
)

// AppError represents a standardized application error.
type AppError struct {
	Code       constants.ErrorCode `json:"code"`
	Message    string              `json:"message"`
	HTTPStatus int                 `json:"-"` // Omit from JSON response
	Details    map[string]any      `json:"details,omitempty"`
	Err        error               `json:"-"` // Omit original error from JSON response
}

// Error returns the string representation of the error.
func (e *AppError) Error() string {
	return fmt.Sprintf("error: code=%s, message=%s", e.Code, e.Message)
}

// Unwrap provides compatibility for Go's errors.Is and errors.As.
func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// WithDetails adds details to the error for structured logging.
func (e *AppError) WithDetails(details map[string]any) *AppError {
	e.Details = details
	return e
}

// WithError wraps an original error.
func (e *AppError) WithError(err error) *AppError {
	e.Err = err
	return e
}

// NewAppError creates a new AppError.
func NewAppError(code constants.ErrorCode, message string, httpStatus int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
	}
}

// Common error constructors

var (
	ErrInternalServer    = NewAppError(constants.ErrCodeInternalServer, "An unexpected error occurred", http.StatusInternalServerError)
	ErrInvalidRequest    = NewAppError(constants.ErrCodeInvalidRequest, "Invalid request payload", http.StatusBadRequest)
	ErrValidation        = NewAppError(constants.ErrCodeValidationFailed, "Request validation failed", http.StatusBadRequest)
	ErrUnauthorized      = NewAppError(constants.ErrCodeUnauthorized, "Authentication failed", http.StatusUnauthorized)
	ErrForbidden         = NewAppError(constants.ErrCodeForbidden, "Permission denied", http.StatusForbidden)
	ErrNotFound          = NewAppError(constants.ErrCodeNotFound, "Resource not found", http.StatusNotFound)
	ErrRateLimitExceeded = NewAppError(constants.ErrCodeRateLimitExceeded, "Too many requests", http.StatusTooManyRequests)
	ErrInvalidArgument   = NewAppError(constants.ErrCodeInvalidRequest, "Invalid argument", http.StatusBadRequest)
	ErrInvalidUUID       = NewAppError(constants.ErrCodeInvalidRequest, "Invalid UUID format", http.StatusBadRequest)
	ErrTenantInactive    = NewAppError(constants.ErrCodeTenantInactive, "Tenant is inactive", http.StatusBadRequest)
	ErrTooManyRequests   = NewAppError(constants.ErrCodeRateLimitExceeded, "Too many requests", http.StatusTooManyRequests)

	ErrInvalidToken = NewAppError(constants.ErrCodeInvalidToken, "Token is invalid or malformed", http.StatusUnauthorized)
	ErrExpiredToken = NewAppError(constants.ErrCodeExpiredToken, "Token has expired", http.StatusUnauthorized)
	ErrTokenRevoked = NewAppError(constants.ErrCodeTokenRevoked, "Token has been revoked", http.StatusUnauthorized)

	ErrInvalidGrant  = NewAppError(constants.ErrCodeInvalidGrant, "Invalid grant type or credentials", http.StatusBadRequest)
	ErrInvalidClient = NewAppError(constants.ErrCodeInvalidClient, "Client authentication failed", http.StatusUnauthorized)

	ErrDatabase   = NewAppError(constants.ErrCodeDatabaseError, "Database operation failed", http.StatusInternalServerError)
	ErrCache      = NewAppError(constants.ErrCodeCacheError, "Cache operation failed", http.StatusInternalServerError)
	ErrVault      = NewAppError(constants.ErrCodeVaultError, "Secret management operation failed", http.StatusInternalServerError)
	ErrKMSFailure = NewAppError(constants.ErrCodeKMSFailure, "KMS operation failed", http.StatusInternalServerError)
)

// Is checks if the target error is of type AppError and matches the code.
func Is(err error, target *AppError) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == target.Code
	}
	return false
}

// FromError converts a generic error to an AppError.
// If the error is already an AppError, it returns it. Otherwise, it wraps it.
func FromError(err error) *AppError {
	if err == nil {
		return nil
	}
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	// Wrap a generic error with a default internal server error
	return ErrInternalServer.WithError(err)
}

//Personal.AI order the ending
