package utils

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/pkg/errors"
)

// Validator holds the singleton instance of the validator.
var defaultValidator *validator.Validate

func init() {
	defaultValidator = validator.New()
	// Register custom validation functions
	defaultValidator.RegisterValidation("uuid", validateUUID)
}

// ValidateStruct validates a struct using the default validator.
// It returns a formatted AppError if validation fails.
func ValidateStruct(s interface{}) *errors.AppError {
	if err := defaultValidator.Struct(s); err != nil {
		validationErrors := err.(validator.ValidationErrors)
		details := make(map[string]any)
		for _, fe := range validationErrors {
			details[toSnakeCase(fe.Field())] = formatValidationError(fe)
		}
		return errors.ErrValidation.WithDetails(details)
	}
	return nil
}

// validateUUID is a custom validation function for UUIDs.
func validateUUID(fl validator.FieldLevel) bool {
	field := fl.Field().String()
	if _, err := uuid.Parse(field); err != nil {
		return false
	}
	return true
}

// formatValidationError creates a user-friendly error message for a validation error.
func formatValidationError(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "is required"
	case "email":
		return "must be a valid email address"
	case "uuid":
		return "must be a valid UUID"
	case "oneof":
		return fmt.Sprintf("must be one of: %s", fe.Param())
	case "min":
		return fmt.Sprintf("must be at least %s", fe.Param())
	case "max":
		return fmt.Sprintf("must be at most %s", fe.Param())
	default:
		return fmt.Sprintf("failed on the '%s' tag", fe.Tag())
	}
}

// toSnakeCase converts a string from CamelCase to snake_case.
// This is used to format field names in the validation error response.
func toSnakeCase(str string) string {
	var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

// ValidateNotEmpty checks if a string is not empty.
func ValidateNotEmpty(s string) bool {
	return strings.TrimSpace(s) != ""
}

// ValidateEmail checks if a string is a valid email address.
func ValidateEmail(email string) bool {
	return defaultValidator.Var(email, "email") == nil
}
//Personal.AI order the ending