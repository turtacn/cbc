// Package utils provides utility functions for the CBC Auth Service.
// This file contains validation functions for input data, ensuring data integrity and security.
package utils

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"crypto/rand"
	"encoding/base64"
	"unicode"
	"unicode/utf8"

	"github.com/turtacn/cbc/pkg/constants"
	"github.com/google/uuid"
)

// ================================================================================
// Validation Error Types
// ================================================================================

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
	Code    string
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(field, message, code string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
		Code:    code,
	}
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []*ValidationError

// Error implements the error interface
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}

	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}

	return strings.Join(messages, "; ")
}

// HasErrors returns true if there are validation errors
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// AddError adds a validation error to the list
func (e *ValidationErrors) AddError(field, message, code string) {
	*e = append(*e, NewValidationError(field, message, code))
}

// ================================================================================
// String Validation
// ================================================================================

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if a string is not empty
func IsNotEmpty(s string) bool {
	return !IsEmpty(s)
}

// ValidateStringLength validates string length
func ValidateStringLength(field, value string, minLen, maxLen int) error {
	length := utf8.RuneCountInString(value)

	if length < minLen {
		return NewValidationError(
			field,
			fmt.Sprintf("must be at least %d characters long", minLen),
			"STRING_TOO_SHORT",
		)
	}

	if maxLen > 0 && length > maxLen {
		return NewValidationError(
			field,
			fmt.Sprintf("must not exceed %d characters", maxLen),
			"STRING_TOO_LONG",
		)
	}

	return nil
}

// ValidateRequired validates that a required field is not empty
func ValidateRequired(field, value string) error {
	if IsEmpty(value) {
		return NewValidationError(
			field,
			"is required and cannot be empty",
			"REQUIRED_FIELD",
		)
	}
	return nil
}

// ValidateAlphanumeric validates that a string contains only alphanumeric characters
func ValidateAlphanumeric(field, value string) error {
	if IsEmpty(value) {
		return nil // Allow empty if not required
	}

	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return NewValidationError(
				field,
				"must contain only alphanumeric characters",
				"INVALID_ALPHANUMERIC",
			)
		}
	}

	return nil
}

// ValidateAlphanumericWithDash validates alphanumeric with dashes and underscores
func ValidateAlphanumericWithDash(field, value string) error {
	if IsEmpty(value) {
		return nil
	}

	for _, r := range value {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return NewValidationError(
				field,
				"must contain only alphanumeric characters, dashes, and underscores",
				"INVALID_FORMAT",
			)
		}
	}

	return nil
}

// ================================================================================
// Email Validation
// ================================================================================

// ValidateEmail validates an email address
func ValidateEmail(field, email string) error {
	if IsEmpty(email) {
		return NewValidationError(field, "email is required", "REQUIRED_FIELD")
	}

	// Parse email using net/mail package
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return NewValidationError(field, "invalid email format", "INVALID_EMAIL")
	}

	// Additional checks
	if len(addr.Address) > 254 {
		return NewValidationError(field, "email address is too long", "EMAIL_TOO_LONG")
	}

	// Check for common disposable email domains (optional security measure)
	parts := strings.Split(addr.Address, "@")
	if len(parts) != 2 {
		return NewValidationError(field, "invalid email format", "INVALID_EMAIL")
	}

	domain := strings.ToLower(parts[1])
	disposableDomains := []string{
		"tempmail.com", "throwaway.email", "guerrillamail.com",
		"10minutemail.com", "mailinator.com",
	}

	for _, disposable := range disposableDomains {
		if domain == disposable {
			return NewValidationError(
				field,
				"disposable email addresses are not allowed",
				"DISPOSABLE_EMAIL",
			)
		}
	}

	return nil
}

// ================================================================================
// URL Validation
// ================================================================================

// ValidateURL validates a URL
func ValidateURL(field, urlStr string) error {
	if IsEmpty(urlStr) {
		return NewValidationError(field, "URL is required", "REQUIRED_FIELD")
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return NewValidationError(field, "invalid URL format", "INVALID_URL")
	}

	// Ensure scheme is present
	if parsedURL.Scheme == "" {
		return NewValidationError(field, "URL must include a scheme (http/https)", "MISSING_SCHEME")
	}

	// Ensure host is present
	if parsedURL.Host == "" {
		return NewValidationError(field, "URL must include a host", "MISSING_HOST")
	}

	return nil
}

// ValidateHTTPSURL validates that a URL uses HTTPS
func ValidateHTTPSURL(field, urlStr string) error {
	if err := ValidateURL(field, urlStr); err != nil {
		return err
	}

	parsedURL, _ := url.Parse(urlStr)
	if parsedURL.Scheme != "https" {
		return NewValidationError(
			field,
			"URL must use HTTPS protocol",
			"HTTPS_REQUIRED",
		)
	}

	return nil
}

// ValidateRedirectURI validates a redirect URI (for OAuth2)
func ValidateRedirectURI(field, uri string) error {
	if err := ValidateURL(field, uri); err != nil {
		return err
	}

	parsedURL, _ := url.Parse(uri)

	// Disallow fragments in redirect URIs (OAuth2 security requirement)
	if parsedURL.Fragment != "" {
		return NewValidationError(
			field,
			"redirect URI must not contain fragments",
			"FRAGMENT_NOT_ALLOWED",
		)
	}

	// Ensure no localhost in production (should be configured via environment)
	if strings.Contains(parsedURL.Host, "localhost") || strings.Contains(parsedURL.Host, "127.0.0.1") {
		// This is a warning check - in production, you might want to enforce this
		// For now, we'll allow it but it should be validated by configuration
	}

	return nil
}

// ================================================================================
// UUID Validation
// ================================================================================

// ValidateUUID validates a UUID string
func ValidateUUID(field, value string) error {
	if IsEmpty(value) {
		return NewValidationError(field, "UUID is required", "REQUIRED_FIELD")
	}

	if _, err := uuid.Parse(value); err != nil {
		return NewValidationError(field, "invalid UUID format", "INVALID_UUID")
	}

	return nil
}

// IsValidUUID checks if a string is a valid UUID without returning an error
func IsValidUUID(value string) bool {
	_, err := uuid.Parse(value)
	return err == nil
}

// ================================================================================
// Tenant and Agent ID Validation
// ================================================================================

// ValidateTenantID validates a tenant ID
func ValidateTenantID(tenantID string) error {
	if err := ValidateRequired("tenant_id", tenantID); err != nil {
		return err
	}

	// Tenant ID should be a valid UUID
	if err := ValidateUUID("tenant_id", tenantID); err != nil {
		return err
	}

	return nil
}

// ValidateAgentID validates an agent ID
func ValidateAgentID(agentID string) error {
	if err := ValidateRequired("agent_id", agentID); err != nil {
		return err
	}

	// Agent ID should be a valid UUID
	if err := ValidateUUID("agent_id", agentID); err != nil {
		return err
	}

	return nil
}

// ValidateClientID validates a client ID
func ValidateClientID(clientID string) error {
	if err := ValidateRequired("client_id", clientID); err != nil {
		return err
	}

	// Client ID format: alphanumeric with dashes
	if err := ValidateStringLength("client_id", clientID, 8, 64); err != nil {
		return err
	}

	if err := ValidateAlphanumericWithDash("client_id", clientID); err != nil {
		return err
	}

	return nil
}

// ================================================================================
// Token Validation
// ================================================================================

// ValidateJWT validates a JWT token format (basic structure check)
func ValidateJWT(field, token string) error {
	if IsEmpty(token) {
		return NewValidationError(field, "token is required", "REQUIRED_FIELD")
	}

	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return NewValidationError(
			field,
			"invalid JWT format (expected 3 parts separated by dots)",
			"INVALID_JWT_FORMAT",
		)
	}

	// Basic validation: each part should be non-empty
	for i, part := range parts {
		if len(part) == 0 {
			return NewValidationError(
				field,
				fmt.Sprintf("JWT part %d is empty", i+1),
				"INVALID_JWT_FORMAT",
			)
		}
	}

	return nil
}

// ValidateBearerToken validates a Bearer token format
func ValidateBearerToken(authHeader string) (string, error) {
	if IsEmpty(authHeader) {
		return "", NewValidationError(
			"authorization",
			"authorization header is required",
			"MISSING_AUTHORIZATION",
		)
	}

	// Check for "Bearer " prefix
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", NewValidationError(
			"authorization",
			"authorization header must use Bearer scheme",
			"INVALID_AUTHORIZATION_SCHEME",
		)
	}

	// Extract token
	token := strings.TrimPrefix(authHeader, bearerPrefix)
	token = strings.TrimSpace(token)

	if IsEmpty(token) {
		return "", NewValidationError(
			"authorization",
			"bearer token is empty",
			"EMPTY_BEARER_TOKEN",
		)
	}

	return token, nil
}

// ================================================================================
// Scope Validation
// ================================================================================

// ValidateScope validates OAuth2 scopes
func ValidateScope(field, scope string) error {
	if IsEmpty(scope) {
		return nil // Scope is optional in some flows
	}

	// Scopes are space-separated
	scopes := strings.Fields(scope)

	for _, s := range scopes {
		// Each scope should be alphanumeric with optional dots, colons, and dashes
		if !isValidScopeFormat(s) {
			return NewValidationError(
				field,
				fmt.Sprintf("invalid scope format: %s", s),
				"INVALID_SCOPE_FORMAT",
			)
		}
	}

	return nil
}

// isValidScopeFormat checks if a single scope has valid format
func isValidScopeFormat(scope string) bool {
	// Scope format: alphanumeric with dots, colons, and dashes
	// Examples: "read", "write:agent", "agent.config.read"
	pattern := `^[a-zA-Z0-9._:-]+$`
	matched, _ := regexp.MatchString(pattern, scope)
	return matched
}

// ValidateGrantType validates OAuth2 grant types
func ValidateGrantType(grantType string) error {
	validGrantTypes := []constants.GrantType{
		constants.GrantTypeClientCredentials,
		constants.GrantTypeAuthorizationCode,
		constants.GrantTypeRefreshToken,
		constants.GrantTypePassword,
	}

	for _, valid := range validGrantTypes {
		if string(valid) == grantType {
			return nil
		}
	}

	return NewValidationError(
		"grant_type",
		fmt.Sprintf("unsupported grant type: %s", grantType),
		"UNSUPPORTED_GRANT_TYPE",
	)
}

// ================================================================================
// IP Address Validation
// ================================================================================

// ValidateIPAddress validates an IP address (IPv4 or IPv6)
func ValidateIPAddress(field, ipAddr string) error {
	if IsEmpty(ipAddr) {
		return NewValidationError(field, "IP address is required", "REQUIRED_FIELD")
	}

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return NewValidationError(field, "invalid IP address format", "INVALID_IP")
	}

	return nil
}

// IsPrivateIP checks if an IP address is private
func IsPrivateIP(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

// ================================================================================
// Security Validation
// ================================================================================

// ValidateNoSQLInjection checks for potential SQL injection patterns
func ValidateNoSQLInjection(field, value string) error {
	if IsEmpty(value) {
		return nil
	}

	// List of suspicious SQL patterns
	sqlPatterns := []string{
		"'", "\"", ";", "--", "/*", "*/", "xp_", "sp_",
		"union", "select", "insert", "update", "delete", "drop",
		"exec", "execute", "script", "javascript", "onerror",
	}

	valueLower := strings.ToLower(value)
	for _, pattern := range sqlPatterns {
		if strings.Contains(valueLower, pattern) {
			return NewValidationError(
				field,
				"contains potentially dangerous characters or keywords",
				"SECURITY_VIOLATION",
			)
		}
	}

	return nil
}

// ValidateNoXSS checks for potential XSS patterns
func ValidateNoXSS(field, value string) error {
	if IsEmpty(value) {
		return nil
	}

	// List of suspicious XSS patterns
	xssPatterns := []string{
		"<script", "</script", "javascript:", "onerror=", "onload=",
		"onclick=", "onmouseover=", "<iframe", "<object", "<embed",
	}

	valueLower := strings.ToLower(value)
	for _, pattern := range xssPatterns {
		if strings.Contains(valueLower, pattern) {
			return NewValidationError(
				field,
				"contains potentially dangerous HTML/JavaScript",
				"XSS_VIOLATION",
			)
		}
	}

	return nil
}

// ValidateNoPathTraversal checks for path traversal attempts
func ValidateNoPathTraversal(field, value string) error {
	if IsEmpty(value) {
		return nil
	}

	// Check for path traversal patterns
	dangerousPatterns := []string{
		"../", "..\\", "..", "%2e%2e", "%252e", "..%2f", "..%5c",
	}

	valueLower := strings.ToLower(value)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(valueLower, pattern) {
			return NewValidationError(
				field,
				"contains path traversal patterns",
				"PATH_TRAVERSAL_VIOLATION",
			)
		}
	}

	return nil
}

// SanitizeInput sanitizes user input by removing dangerous characters
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	// Remove control characters (except newlines and tabs in some contexts)
	var builder strings.Builder
	for _, r := range input {
		if r == '\n' || r == '\r' || r == '\t' || !unicode.IsControl(r) {
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

// ================================================================================
// Numeric Validation
// ================================================================================

// ValidateIntRange validates that an integer is within a specified range
func ValidateIntRange(field string, value, min, max int) error {
	if value < min {
		return NewValidationError(
			field,
			fmt.Sprintf("must be at least %d", min),
			"VALUE_TOO_SMALL",
		)
	}

	if value > max {
		return NewValidationError(
			field,
			fmt.Sprintf("must not exceed %d", max),
			"VALUE_TOO_LARGE",
		)
	}

	return nil
}

// ValidatePositive validates that a number is positive
func ValidatePositive(field string, value int) error {
	if value <= 0 {
		return NewValidationError(
			field,
			"must be a positive number",
			"NEGATIVE_VALUE",
		)
	}
	return nil
}

// ================================================================================
// Enum Validation
// ================================================================================

// ValidateEnum validates that a value is one of the allowed enum values
func ValidateEnum(field, value string, allowedValues []string) error {
	if IsEmpty(value) {
		return NewValidationError(field, "value is required", "REQUIRED_FIELD")
	}

	for _, allowed := range allowedValues {
		if value == allowed {
			return nil
		}
	}

	return NewValidationError(
		field,
		fmt.Sprintf("invalid value, must be one of: %s", strings.Join(allowedValues, ", ")),
		"INVALID_ENUM_VALUE",
	)
}

// ================================================================================
// Batch Validation
// ================================================================================

// Validator is a function type for validation
type Validator func() error

// ValidateAll runs multiple validators and collects all errors
func ValidateAll(validators ...Validator) ValidationErrors {
	var errors ValidationErrors

	for _, validator := range validators {
		if err := validator(); err != nil {
			if ve, ok := err.(*ValidationError); ok {
				errors = append(errors, ve)
			} else if ves, ok := err.(ValidationErrors); ok {
				errors = append(errors, ves...)
			}
		}
	}

	return errors
}

// ================================================================================
// Password Validation
// ================================================================================

// PasswordStrength represents password strength levels
type PasswordStrength int

const (
	PasswordStrengthWeak PasswordStrength = iota
	PasswordStrengthMedium
	PasswordStrengthStrong
)

// ValidatePassword validates password strength
func ValidatePassword(field, password string) error {
	if err := ValidateRequired(field, password); err != nil {
		return err
	}

	// Minimum length
	if len(password) < 8 {
		return NewValidationError(
			field,
			"password must be at least 8 characters long",
			"PASSWORD_TOO_SHORT",
		)
	}

	// Maximum length (to prevent DoS)
	if len(password) > 128 {
		return NewValidationError(
			field,
			"password must not exceed 128 characters",
			"PASSWORD_TOO_LONG",
		)
	}

	// Check for required character types
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return NewValidationError(
			field,
			"password must contain uppercase, lowercase, digit, and special character",
			"PASSWORD_TOO_WEAK",
		)
	}

	return nil
}

// CalculatePasswordStrength calculates the strength of a password
func CalculatePasswordStrength(password string) PasswordStrength {
	if len(password) < 8 {
		return PasswordStrengthWeak
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	score := 0
	if hasUpper {
		score++
	}
	if hasLower {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}
	if len(password) >= 12 {
		score++
	}

	if score >= 4 {
		return PasswordStrengthStrong
	} else if score >= 3 {
		return PasswordStrengthMedium
	}

	return PasswordStrengthWeak
}


// ValidateStruct validates a struct based on tags.
func ValidateStruct(s interface{}) error {
	// This is a placeholder implementation.
	// In a real application, you would use a library like go-playground/validator.
	return nil
}

// GenerateSecureRandomString generates a URL-safe, base64 encoded secure random string.
func GenerateSecureRandomString(len int) (string, error) {
	bytes := make([]byte, len)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

//Personal.AI order the ending
