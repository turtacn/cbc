package constants

// TokenType defines the type of a token.
type TokenType string

const (
	AccessToken  TokenType = "access_token"
	RefreshToken TokenType = "refresh_token"
)

// AlgorithmType defines the type of a cryptographic algorithm.
type AlgorithmType string

const (
	RS256 AlgorithmType = "RS256"
	ES256 AlgorithmType = "ES256"
)

// RateLimitScope defines the scope for rate limiting.
type RateLimitScope string

const (
	RateLimitScopeTenant RateLimitScope = "tenant"
	RateLimitScopeDevice RateLimitScope = "device"
	RateLimitScopeIP     RateLimitScope = "ip"
	RateLimitScopeGlobal RateLimitScope = "global"
)

// Cache-related constants
const (
	DefaultCacheTTL      = 5 * time.Minute
	TenantConfigCacheTTL = 10 * time.Minute
	PublicKeyCacheTTL    = 1 * time.Hour
	TokenBlacklistTTL    = 24 * time.Hour
)

// HTTPStatus related constants
const (
	StatusClientClosedRequest = 499
)

// ErrorCode defines standardized error codes for the application.
type ErrorCode string

const (
	ErrCodeUnknown               ErrorCode = "UNKNOWN_ERROR"
	ErrCodeInternalServer        ErrorCode = "INTERNAL_SERVER_ERROR"
	ErrCodeInvalidRequest        ErrorCode = "INVALID_REQUEST"
	ErrCodeValidationFailed      ErrorCode = "VALIDATION_FAILED"
	ErrCodeNotFound              ErrorCode = "NOT_FOUND"
	ErrCodeUnauthorized          ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden             ErrorCode = "FORBIDDEN"
	ErrCodeRateLimitExceeded     ErrorCode = "RATE_LIMIT_EXCEEDED"
	ErrCodeInvalidToken          ErrorCode = "INVALID_TOKEN"
	ErrCodeExpiredToken          ErrorCode = "EXPIRED_TOKEN"
	ErrCodeTokenRevoked          ErrorCode = "TOKEN_REVOKED"
	ErrCodeInvalidGrant          ErrorCode = "INVALID_GRANT"
	ErrCodeInvalidClient         ErrorCode = "INVALID_CLIENT"
	ErrCodeDeviceNotRegistered   ErrorCode = "DEVICE_NOT_REGISTERED"
	ErrCodeTenantInactive        ErrorCode = "TENANT_INACTIVE"
	ErrCodeDatabaseError         ErrorCode = "DATABASE_ERROR"
	ErrCodeCacheError            ErrorCode = "CACHE_ERROR"
	ErrCodeVaultError            ErrorCode = "VAULT_ERROR"
	ErrCodeKMSFailure            ErrorCode = "KMS_FAILURE"
)

// AuditEventType defines the type of an audit event.
type AuditEventType string

const (
	AuditEventTypeDeviceRegister  AuditEventType = "device.register"
	AuditEventTypeTokenIssue      AuditEventType = "token.issue"
	AuditEventTypeTokenRefresh    AuditEventType = "token.refresh"
	AuditEventTypeTokenRevoke     AuditEventType = "token.revoke"
	AuditEventTypeTokenVerify     AuditEventType = "token.verify"
	AuditEventTypeKeyRotation     AuditEventType = "key.rotation"
	AuditEventTypeConfigUpdate    AuditEventType = "config.update"
	AuditEventTypeLoginFailure    AuditEventType = "login.failure"
)

// ContextKey defines keys for storing values in context.
type ContextKey string

const (
    ContextKeyTraceID   ContextKey = "trace_id"
    ContextKeyClaims    ContextKey = "claims"
    ContextKeyLogger    ContextKey = "logger"
)
//Personal.AI order the ending