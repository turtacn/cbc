// Package utils provides utility functions for the CBC Auth Service.
// This file contains data conversion, transformation, and formatting utilities.
package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ================================================================================
// String Conversion
// ================================================================================

// StringToInt converts a string to an integer with default value on error
func StringToInt(s string, defaultValue int) int {
	if val, err := strconv.Atoi(s); err == nil {
		return val
	}
	return defaultValue
}

// StringToInt64 converts a string to int64 with default value on error
func StringToInt64(s string, defaultValue int64) int64 {
	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		return val
	}
	return defaultValue
}

// StringToBool converts a string to boolean
func StringToBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes" || s == "on"
}

// StringToFloat64 converts a string to float64 with default value on error
func StringToFloat64(s string, defaultValue float64) float64 {
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		return val
	}
	return defaultValue
}

// IntToString converts an integer to string
func IntToString(i int) string {
	return strconv.Itoa(i)
}

// Int64ToString converts int64 to string
func Int64ToString(i int64) string {
	return strconv.FormatInt(i, 10)
}

// BoolToString converts boolean to string
func BoolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ================================================================================
// JSON Conversion
// ================================================================================

// ToJSON converts an object to JSON string
func ToJSON(v interface{}) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	return string(bytes), nil
}

// ToJSONPretty converts an object to pretty-printed JSON string
func ToJSONPretty(v interface{}) (string, error) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	return string(bytes), nil
}

// FromJSON parses JSON string into an object
func FromJSON(jsonStr string, v interface{}) error {
	if err := json.Unmarshal([]byte(jsonStr), v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nil
}

// ToJSONBytes converts an object to JSON bytes
func ToJSONBytes(v interface{}) ([]byte, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to JSON bytes: %w", err)
	}
	return bytes, nil
}

// FromJSONBytes parses JSON bytes into an object
func FromJSONBytes(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal JSON bytes: %w", err)
	}
	return nil
}

// MustToJSON converts to JSON and panics on error (use carefully)
func MustToJSON(v interface{}) string {
	result, err := ToJSON(v)
	if err != nil {
		panic(err)
	}
	return result
}

// ================================================================================
// Base64 Encoding/Decoding
// ================================================================================

// Base64Encode encodes bytes to base64 string
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes base64 string to bytes
func Base64Decode(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return decoded, nil
}

// Base64URLEncode encodes bytes to URL-safe base64 string
func Base64URLEncode(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes URL-safe base64 string to bytes
func Base64URLDecode(encoded string) ([]byte, error) {
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode URL-safe base64: %w", err)
	}
	return decoded, nil
}

// Base64EncodeString encodes string to base64 string
func Base64EncodeString(s string) string {
	return Base64Encode([]byte(s))
}

// Base64DecodeString decodes base64 string to string
func Base64DecodeString(encoded string) (string, error) {
	decoded, err := Base64Decode(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// ================================================================================
// Time Conversion
// ================================================================================

// TimeToUnix converts time.Time to Unix timestamp (seconds)
func TimeToUnix(t time.Time) int64 {
	return t.Unix()
}

// UnixToTime converts Unix timestamp to time.Time
func UnixToTime(timestamp int64) time.Time {
	return time.Unix(timestamp, 0)
}

// TimeToUnixMilli converts time.Time to Unix timestamp (milliseconds)
func TimeToUnixMilli(t time.Time) int64 {
	return t.UnixMilli()
}

// UnixMilliToTime converts Unix timestamp (milliseconds) to time.Time
func UnixMilliToTime(timestamp int64) time.Time {
	return time.UnixMilli(timestamp)
}

// TimeToISO8601 converts time.Time to ISO 8601 string
func TimeToISO8601(t time.Time) string {
	return t.Format(time.RFC3339)
}

// ISO8601ToTime parses ISO 8601 string to time.Time
func ISO8601ToTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse ISO 8601 time: %w", err)
	}
	return t, nil
}

// TimeToString converts time.Time to formatted string
func TimeToString(t time.Time, layout string) string {
	if layout == "" {
		layout = "2006-01-02 15:04:05"
	}
	return t.Format(layout)
}

// StringToTime parses formatted string to time.Time
func StringToTime(s string, layout string) (time.Time, error) {
	if layout == "" {
		layout = "2006-01-02 15:04:05"
	}
	t, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse time string: %w", err)
	}
	return t, nil
}

// DurationToSeconds converts time.Duration to seconds
func DurationToSeconds(d time.Duration) int64 {
	return int64(d.Seconds())
}

// SecondsToDuration converts seconds to time.Duration
func SecondsToDuration(seconds int64) time.Duration {
	return time.Duration(seconds) * time.Second
}

// ================================================================================
// Map/Struct Conversion
// ================================================================================

// StructToMap converts a struct to map using JSON marshaling
func StructToMap(v interface{}) (map[string]interface{}, error) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to map: %w", err)
	}

	return result, nil
}

// MapToStruct converts a map to struct using JSON marshaling
func MapToStruct(m map[string]interface{}, v interface{}) error {
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal map: %w", err)
	}

	if err := json.Unmarshal(jsonBytes, v); err != nil {
		return fmt.Errorf("failed to unmarshal to struct: %w", err)
	}

	return nil
}

// MergeMap merges two maps (source values override destination)
func MergeMap(dest, source map[string]interface{}) map[string]interface{} {
	if dest == nil {
		dest = make(map[string]interface{})
	}

	for key, value := range source {
		dest[key] = value
	}

	return dest
}

// CopyMap creates a shallow copy of a map
func CopyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(m))
	for key, value := range m {
		result[key] = value
	}
	return result
}

// ================================================================================
// String Formatting
// ================================================================================

// FormatFileSize formats bytes to human-readable string
func FormatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// FormatDuration formats duration to human-readable string
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

// Truncate truncates a string to specified length with ellipsis
func Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	if maxLen <= 3 {
		return s[:maxLen]
	}

	return s[:maxLen-3] + "..."
}

// PadLeft pads string to the left with specified character
func PadLeft(s string, length int, pad rune) string {
	if len(s) >= length {
		return s
	}
	return strings.Repeat(string(pad), length-len(s)) + s
}

// PadRight pads string to the right with specified character
func PadRight(s string, length int, pad rune) string {
	if len(s) >= length {
		return s
	}
	return s + strings.Repeat(string(pad), length-len(s))
}

// ================================================================================
// Data Masking/Obfuscation
// ================================================================================

// MaskEmail masks email address (e.g., "test@example.com" -> "t**t@example.com")
func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "***"
	}

	localPart := parts[0]
	domain := parts[1]

	if len(localPart) <= 2 {
		return strings.Repeat("*", len(localPart)) + "@" + domain
	}

	masked := string(localPart[0]) + strings.Repeat("*", len(localPart)-2) + string(localPart[len(localPart)-1])
	return masked + "@" + domain
}

// MaskPhoneNumber masks phone number (e.g., "+1234567890" -> "+1****7890")
func MaskPhoneNumber(phone string) string {
	if len(phone) <= 6 {
		return strings.Repeat("*", len(phone))
	}

	prefix := phone[:2]
	suffix := phone[len(phone)-4:]
	masked := strings.Repeat("*", len(phone)-6)

	return prefix + masked + suffix
}

// MaskString masks a string, showing only first and last characters
func MaskString(s string, showChars int) string {
	length := len(s)
	if length <= showChars*2 {
		return strings.Repeat("*", length)
	}

	prefix := s[:showChars]
	suffix := s[length-showChars:]
	masked := strings.Repeat("*", length-showChars*2)

	return prefix + masked + suffix
}

// MaskToken masks a token, showing only first 8 characters
func MaskToken(token string) string {
	if len(token) <= 8 {
		return strings.Repeat("*", len(token))
	}
	return token[:8] + strings.Repeat("*", len(token)-8)
}

// MaskCreditCard masks credit card number
func MaskCreditCard(cardNumber string) string {
	// Remove spaces and dashes
	cleaned := strings.ReplaceAll(cardNumber, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	if len(cleaned) < 12 {
		return strings.Repeat("*", len(cleaned))
	}

	// Show first 4 and last 4 digits
	return cleaned[:4] + strings.Repeat("*", len(cleaned)-8) + cleaned[len(cleaned)-4:]
}

// ================================================================================
// Slice Conversion
// ================================================================================

// StringSliceToInterfaceSlice converts []string to []interface{}
func StringSliceToInterfaceSlice(slice []string) []interface{} {
	result := make([]interface{}, len(slice))
	for i, v := range slice {
		result[i] = v
	}
	return result
}

// InterfaceSliceToStringSlice converts []interface{} to []string
func InterfaceSliceToStringSlice(slice []interface{}) []string {
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		if str, ok := v.(string); ok {
			result = append(result, str)
		}
	}
	return result
}

// StringSliceToMap converts []string to map[string]bool for quick lookup
func StringSliceToMap(slice []string) map[string]bool {
	result := make(map[string]bool, len(slice))
	for _, v := range slice {
		result[v] = true
	}
	return result
}

// RemoveDuplicates removes duplicate strings from slice
func RemoveDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// ================================================================================
// URL Query Parameters
// ================================================================================

// MapToQueryString converts map to URL query string
func MapToQueryString(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}

	var pairs []string
	for key, value := range params {
		pairs = append(pairs, fmt.Sprintf("%s=%s", key, value))
	}

	return strings.Join(pairs, "&")
}

// QueryStringToMap parses URL query string to map
func QueryStringToMap(query string) map[string]string {
	result := make(map[string]string)

	if query == "" {
		return result
	}

	// Remove leading '?' if present
	query = strings.TrimPrefix(query, "?")

	pairs := strings.Split(query, "&")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}

	return result
}

// ================================================================================
// Pointer Conversion Helpers
// ================================================================================

// StringPtr returns a pointer to the string value
func StringPtr(s string) *string {
	return &s
}

// IntPtr returns a pointer to the int value
func IntPtr(i int) *int {
	return &i
}

// Int64Ptr returns a pointer to the int64 value
func Int64Ptr(i int64) *int64 {
	return &i
}

// BoolPtr returns a pointer to the bool value
func BoolPtr(b bool) *bool {
	return &b
}

// TimePtr returns a pointer to the time.Time value
func TimePtr(t time.Time) *time.Time {
	return &t
}

// StringValue returns the string value or default if nil
func StringValue(s *string, defaultValue string) string {
	if s == nil {
		return defaultValue
	}
	return *s
}

// IntValue returns the int value or default if nil
func IntValue(i *int, defaultValue int) int {
	if i == nil {
		return defaultValue
	}
	return *i
}

// Int64Value returns the int64 value or default if nil
func Int64Value(i *int64, defaultValue int64) int64 {
	if i == nil {
		return defaultValue
	}
	return *i
}

// BoolValue returns the bool value or default if nil
func BoolValue(b *bool, defaultValue bool) bool {
	if b == nil {
		return defaultValue
	}
	return *b
}

// TimeValue returns the time.Time value or default if nil
func TimeValue(t *time.Time, defaultValue time.Time) time.Time {
	if t == nil {
		return defaultValue
	}
	return *t
}

// ================================================================================
// Case Conversion
// ================================================================================

// ToSnakeCase converts string to snake_case
func ToSnakeCase(s string) string {
	var result strings.Builder

	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('_')
		}
		result.WriteRune(r)
	}

	return strings.ToLower(result.String())
}

// ToCamelCase converts string to camelCase
func ToCamelCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	if len(words) == 0 {
		return s
	}

	result := strings.ToLower(words[0])
	for i := 1; i < len(words); i++ {
		result += strings.Title(strings.ToLower(words[i]))
	}

	return result
}

// ToPascalCase converts string to PascalCase
func ToPascalCase(s string) string {
	words := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-' || r == ' '
	})

	var result strings.Builder
	for _, word := range words {
		result.WriteString(strings.Title(strings.ToLower(word)))
	}

	return result.String()
}

// ToKebabCase converts string to kebab-case
func ToKebabCase(s string) string {
	var result strings.Builder

	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune('-')
		}
		result.WriteRune(r)
	}

	return strings.ToLower(result.String())
}

// ================================================================================
// Default Value Helpers
// ================================================================================

// DefaultString returns the value if not empty, otherwise returns the default
func DefaultString(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// DefaultInt returns the value if not zero, otherwise returns the default
func DefaultInt(value, defaultValue int) int {
	if value == 0 {
		return defaultValue
	}
	return value
}

// DefaultInt64 returns the value if not zero, otherwise returns the default
func DefaultInt64(value, defaultValue int64) int64 {
	if value == 0 {
		return defaultValue
	}
	return value
}

// CoalesceString returns the first non-empty string
func CoalesceString(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ================================================================================
// Array/Slice Helpers
// ================================================================================

// ChunkSlice divides a slice into chunks of specified size
func ChunkSlice(slice []string, chunkSize int) [][]string {
	if chunkSize <= 0 {
		return nil
	}

	var chunks [][]string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}

	return chunks
}

// Contains checks if a slice contains a value
func Contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// Filter filters a slice based on a predicate function
func Filter(slice []string, predicate func(string) bool) []string {
	result := make([]string, 0)
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

// Map applies a transformation function to each element
func Map(slice []string, transform func(string) string) []string {
	result := make([]string, len(slice))
	for i, item := range slice {
		result[i] = transform(item)
	}
	return result
}

//Personal.AI order the ending
