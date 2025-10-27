package errors

import "github.com/turtacn/cbc/pkg/constants"

// Code defines the type for error codes.
type Code string

const (
	// CodeInvalidArgument indicates a client-specified argument is invalid.
	CodeInvalidArgument = "invalid_argument"
	// CodeUnauthorized indicates a request is not authorized.
	CodeUnauthorized = "unauthorized"
	// CodeInternal indicates an internal server error.
	CodeInternal = "internal"
	// CodeNotFound indicates a resource was not found.
	CodeNotFound = "not_found"
	// CodeConflict indicates a conflict with the current state of the resource.
	CodeConflict = "conflict"
	// CodePermissionDenied indicates a permission denied error.
	CodePermissionDenied = "permission_denied"
)

var (
	// ErrInvalidInput is a compatibility variable for existing code.
	ErrInvalidInput = CodeInvalidArgument
	// ErrDatabaseQuery is a compatibility variable for existing code.
	ErrDatabaseQuery = CodeInternal
	// ErrTenantExists is a compatibility variable for existing code.
	ErrTenantExists = CodeConflict
)

// ErrorCode is an alias for Code to maintain compatibility.
type ErrorCode = Code

// New creates a new CBCError.
func New(code Code, msg string, kv ...interface{}) error {
	return NewError(constants.ErrorCode(code), 0, msg, "")
}

// Wrap wraps an error with a new error code and message.
func Wrap(err error, code Code, msg string, kv ...interface{}) error {
	return WrapError(err, constants.ErrorCode(code), msg)
}

// FromConstants converts a constants.ErrorCode to a Code.
func FromConstants(c constants.ErrorCode) Code {
	return Code(c)
}

var (
	// ErrCodeServerError is a compatibility variable for existing code.
	ErrCodeServerError = CodeInternal
)
