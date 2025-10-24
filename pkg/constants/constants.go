// Package constants defines system-wide constants for the CBC Auth Service.
// This package provides type-safe constant definitions used across all modules.
package constants

import "time"

// ================================================================================
// Token Type Constants
// ================================================================================

// TokenType represents the type of authentication token
type TokenType string

const (
	// TokenTypeAccess represents a short-lived access token
	TokenTypeAccess TokenType = "access_token"

	// TokenTypeRefresh represents a long-lived refresh token
	TokenTypeRefresh TokenType = "refresh_token"

	// TokenTypeBearer represents the Bearer token type for HTTP Authorization header
	TokenTypeBearer TokenType = "Bearer"
)

// ================================================================================
// Token Status Constants
// ================================================================================

// TokenStatus represents the lifecycle status of a token
type TokenStatus string

const (
	// TokenStatusActive indicates the token is currently valid
	TokenStatusActive TokenStatus = "active"

	// TokenStatusRevoked indicates the token has been explicitly revoked
	TokenStatusRevoked TokenStatus = "revoked"

	// TokenStatusExpired indicates the token has passed its expiration time
	TokenStatusExpired TokenStatus = "expired"

	// TokenStatusDeprecated indicates the token is still valid but a newer version exists
	TokenStatusDeprecated TokenStatus = "deprecated"
)

// ================================================================================
// JWT Algorithm Constants
// ================================================================================

// JWTAlgorithm represents the signing algorithm for JWT tokens
type JWTAlgorithm string

const (
	// AlgorithmRS256 represents RSA signature with SHA-256 (recommended)
	AlgorithmRS256 JWTAlgorithm = "RS256"

	// AlgorithmRS384 represents RSA signature with SHA-384
	AlgorithmRS384 JWTAlgorithm = "RS384"

	// AlgorithmRS512 represents RSA signature with SHA-512
	AlgorithmRS512 JWTAlgorithm = "RS512"

	// AlgorithmES256 represents ECDSA signature with SHA-256 (future support)
	AlgorithmES256 JWTAlgorithm = "ES256"

	// AlgorithmES384 represents ECDSA signature with SHA-384
	AlgorithmES384 JWTAlgorithm = "ES384"
)

// DefaultJWTAlgorithm is the default algorithm used for token signing
const DefaultJWTAlgorithm = AlgorithmRS256

// ================================================================================
// Token Lifetime Constants
// ================================================================================

const (
	// AccessTokenDefaultTTL is the default lifetime for access tokens (15 minutes)
	AccessTokenDefaultTTL = 15 * time.Minute

	// AccessTokenMinTTL is the minimum allowed lifetime for access tokens (5 minutes)
	AccessTokenMinTTL = 5 * time.Minute

	// AccessTokenMaxTTL is the maximum allowed lifetime for access tokens (1 hour)
	AccessTokenMaxTTL = 1 * time.Hour

	// RefreshTokenDefaultTTL is the default lifetime for refresh tokens (30 days)
	RefreshTokenDefaultTTL = 30 * 24 * time.Hour

	// RefreshTokenMinTTL is the minimum allowed lifetime for refresh tokens (7 days)
	RefreshTokenMinTTL = 7 * 24 * time.Hour

	// RefreshTokenMaxTTL is the maximum allowed lifetime for refresh tokens (90 days)
	RefreshTokenMaxTTL = 90 * 24 * time.Hour

	// MgrClientAssertionTTL is the lifetime for MGR client assertions (60 seconds)
	MgrClientAssertionTTL = 60 * time.Second

	// JTIBlacklistTTL is the lifetime for JTI blacklist entries (equal to token expiry)
	JTIBlacklistTTL = RefreshTokenMaxTTL
)

// ================================================================================
// Cache TTL Constants
// ================================================================================

const (
	// PublicKeyCacheTTL is the cache lifetime for tenant public keys (4 hours)
	PublicKeyCacheTTL = 4 * time.Hour

	// PublicKeyCacheL1TTL is the L1 (in-memory) cache lifetime for public keys (1 hour)
	PublicKeyCacheL1TTL = 1 * time.Hour

	// RevokedTokenCacheTTL is the cache lifetime for revoked token blacklist
	RevokedTokenCacheTTL = 24 * time.Hour

	// RateLimitWindowTTL is the time window for rate limiting counters (1 minute)
	RateLimitWindowTTL = 1 * time.Minute

	// TenantConfigCacheTTL is the cache lifetime for tenant configurations (30 minutes)
	TenantConfigCacheTTL = 30 * time.Minute
)

// ================================================================================
// Rate Limiting Constants
// ================================================================================

const (
	// GlobalRateLimitQPS is the maximum global requests per second (1 million)
	GlobalRateLimitQPS = 1_000_000

	// TenantRateLimitQPS is the maximum requests per second per tenant (100k)
	TenantRateLimitQPS = 100_000

	// AgentRateLimitQPS is the maximum requests per minute per agent (10)
	AgentRateLimitQPM = 10

	// MgrRateLimitQPS is the maximum registration requests per second per MGR (1k)
	MgrRateLimitQPS = 1_000

	// RateLimitBurstSize is the burst size for token bucket algorithm
	RateLimitBurstSize = 100
)

// RateLimitScope defines the scope level for rate limiting
type RateLimitScope string

const (
	// RateLimitScopeGlobal applies to all requests
	RateLimitScopeGlobal RateLimitScope = "global"

	// RateLimitScopeTenant applies per tenant
	RateLimitScopeTenant RateLimitScope = "tenant"

	// RateLimitScopeAgent applies per agent
	RateLimitScopeAgent RateLimitScope = "agent"

	// RateLimitScopeMgr applies per MGR client
	RateLimitScopeMgr RateLimitScope = "mgr"
)

// ================================================================================
// OAuth 2.0 Grant Type Constants
// ================================================================================

// GrantType represents OAuth 2.0 grant types
type GrantType string

const (
	// GrantTypeClientCredentials is used for MGR device registration
	GrantTypeClientCredentials GrantType = "client_credentials"

	// GrantTypeRefreshToken is used for access token refresh
	GrantTypeRefreshToken GrantType = "refresh_token"

	// GrantTypeDeviceCode is reserved for future device flow support
	GrantTypeDeviceCode GrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// ClientAssertionType represents the type of client assertion
type ClientAssertionType string

const (
	// ClientAssertionTypeJWT is the JWT-based client assertion
	ClientAssertionTypeJWT ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// ================================================================================
// OAuth 2.0 Error Code Constants
// ================================================================================

// ErrorCode represents standard OAuth 2.0 error codes
type ErrorCode string

const (
	// ErrCodeInvalidRequest indicates the request is missing required parameters
	ErrCodeInvalidRequest ErrorCode = "invalid_request"

	// ErrCodeInvalidClient indicates client authentication failed
	ErrCodeInvalidClient ErrorCode = "invalid_client"

	// ErrCodeInvalidGrant indicates the provided grant is invalid or expired
	ErrCodeInvalidGrant ErrorCode = "invalid_grant"

	// ErrCodeUnauthorizedClient indicates the client is not authorized for this grant type
	ErrCodeUnauthorizedClient ErrorCode = "unauthorized_client"

	// ErrCodeUnsupportedGrantType indicates the grant type is not supported
	ErrCodeUnsupportedGrantType ErrorCode = "unsupported_grant_type"

	// ErrCodeInvalidScope indicates the requested scope is invalid or exceeds granted scope
	ErrCodeInvalidScope ErrorCode = "invalid_scope"

	// ErrCodeServerError indicates an internal server error occurred
	ErrCodeServerError ErrorCode = "server_error"

	// ErrCodeTemporarilyUnavailable indicates the service is temporarily unavailable
	ErrCodeTemporarilyUnavailable ErrorCode = "temporarily_unavailable"
)

// ================================================================================
// HTTP Status Code Constants
// ================================================================================

const (
	// HTTPStatusOK indicates successful request (200)
	HTTPStatusOK = 200

	// HTTPStatusCreated indicates successful resource creation (201)
	HTTPStatusCreated = 201

	// HTTPStatusBadRequest indicates client error (400)
	HTTPStatusBadRequest = 400

	// HTTPStatusUnauthorized indicates authentication failure (401)
	HTTPStatusUnauthorized = 401

	// HTTPStatusForbidden indicates authorization failure (403)
	HTTPStatusForbidden = 403

	// HTTPStatusNotFound indicates resource not found (404)
	HTTPStatusNotFound = 404

	// HTTPStatusTooManyRequests indicates rate limit exceeded (429)
	HTTPStatusTooManyRequests = 429

	// HTTPStatusInternalServerError indicates server error (500)
	HTTPStatusInternalServerError = 500

	// HTTPStatusServiceUnavailable indicates service unavailable (503)
	HTTPStatusServiceUnavailable = 503
)

// ================================================================================
// Audit Event Type Constants
// ================================================================================

// AuditEventType represents different types of auditable events
type AuditEventType string

const (
	// EventTypeDeviceRegister represents device registration events
	EventTypeDeviceRegister AuditEventType = "device_register"

	// EventTypeTokenIssue represents token issuance events
	EventTypeTokenIssue AuditEventType = "token_issue"

	// EventTypeTokenRefresh represents token refresh events
	EventTypeTokenRefresh AuditEventType = "token_refresh"

	// EventTypeTokenRevoke represents token revocation events
	EventTypeTokenRevoke AuditEventType = "token_revoke"

	// EventTypeAuthFailure represents authentication failure events
	EventTypeAuthFailure AuditEventType = "auth_failure"

	// EventTypeRateLimitExceeded represents rate limit exceeded events
	EventTypeRateLimitExceeded AuditEventType = "rate_limit_exceeded"

	// EventTypeKeyRotation represents key rotation events
	EventTypeKeyRotation AuditEventType = "key_rotation"

	// EventTypeEmergencyRevocation represents emergency key revocation events
	EventTypeEmergencyRevocation AuditEventType = "emergency_revocation"
)

// AuditEventResult represents the result of an audited event
type AuditEventResult string

const (
	// AuditResultSuccess indicates the event completed successfully
	AuditResultSuccess AuditEventResult = "success"

	// AuditResultFailure indicates the event failed
	AuditResultFailure AuditEventResult = "failure"

	// AuditResultPartial indicates the event partially succeeded
	AuditResultPartial AuditEventResult = "partial"
)

// ================================================================================
// Cache Key Prefix Constants
// ================================================================================

const (
	// CacheKeyPrefixPublicKey is the prefix for tenant public key cache entries
	CacheKeyPrefixPublicKey = "pubkey:"

	// CacheKeyPrefixRevokedToken is the prefix for revoked token blacklist entries
	CacheKeyPrefixRevokedToken = "revoked:"

	// CacheKeyPrefixRateLimit is the prefix for rate limiting counter entries
	CacheKeyPrefixRateLimit = "ratelimit:"

	// CacheKeyPrefixJTI is the prefix for JTI uniqueness check entries
	CacheKeyPrefixJTI = "jti:"

	// CacheKeyPrefixTenantConfig is the prefix for tenant configuration cache entries
	CacheKeyPrefixTenantConfig = "tenant:config:"

	// CacheKeyPrefixMgrClient is the prefix for MGR client metadata cache entries
	CacheKeyPrefixMgrClient = "mgr:client:"
)

// ================================================================================
// Database Table Name Constants
// ================================================================================

const (
	// TableNameTokenMetadata is the name of the token metadata table
	TableNameTokenMetadata = "token_metadata"

	// TableNameAuditLogs is the name of the audit logs table
	TableNameAuditLogs = "audit_logs"

	// TableNameTenantConfigs is the name of the tenant configurations table
	TableNameTenantConfigs = "tenant_configs"

	// TableNameMgrConfigs is the name of the MGR configurations table
	TableNameMgrConfigs = "mgr_configs"

	// TableNameDeviceMetadata is the name of the device metadata table
	TableNameDeviceMetadata = "device_metadata"
)

// ================================================================================
// Vault Path Constants
// ================================================================================

const (
	// VaultSecretPathPrefix is the base path for CBC secrets in Vault
	VaultSecretPathPrefix = "secret/cbc"

	// VaultTenantKeysPath is the path template for tenant keys
	VaultTenantKeysPath = "secret/cbc/tenants/%s/keys/%s"

	// VaultMgrPublicKeysPath is the path template for MGR public keys
	VaultMgrPublicKeysPath = "secret/cbc/mgr/%s/public-keys"
)

// ================================================================================
// Key Management Constants
// ================================================================================

// KeyStatus represents the status of a cryptographic key
type KeyStatus string

const (
	// KeyStatusActive indicates the key is actively used for signing and verification
	KeyStatusActive KeyStatus = "active"

	// KeyStatusDeprecated indicates the key is only used for verification (not signing)
	KeyStatusDeprecated KeyStatus = "deprecated"

	// KeyStatusRevoked indicates the key must not be used at all
	KeyStatusRevoked KeyStatus = "revoked"
)

const (
	// KeyRotationDefaultInterval is the default key rotation interval (60 days)
	KeyRotationDefaultInterval = 60 * 24 * time.Hour

	// KeyRotationMinInterval is the minimum key rotation interval (30 days)
	KeyRotationMinInterval = 30 * 24 * time.Hour

	// KeyRotationMaxInterval is the maximum key rotation interval (90 days)
	KeyRotationMaxInterval = 90 * 24 * time.Hour

	// KeyRotationGracePeriod is the grace period for deprecated keys (30 days)
	KeyRotationGracePeriod = 30 * 24 * time.Hour

	// RSAKeySize is the default RSA key size (4096 bits)
	RSAKeySize = 4096
)

// ================================================================================
// Device Trust Level Constants
// ================================================================================

// DeviceTrustLevel represents the trust level of a device
type DeviceTrustLevel string

const (
	// TrustLevelHigh indicates high trust (TPM/TEE bound, hardware fingerprint)
	TrustLevelHigh DeviceTrustLevel = "high"

	// TrustLevelMedium indicates medium trust (software fingerprint, behavior pattern)
	TrustLevelMedium DeviceTrustLevel = "medium"

	// TrustLevelLow indicates low trust (basic identification only)
	TrustLevelLow DeviceTrustLevel = "low"

	// TrustLevelUntrusted indicates untrusted device (anomalous behavior detected)
	TrustLevelUntrusted DeviceTrustLevel = "untrusted"
)

// ================================================================================
// Tenant Status Constants
// ================================================================================

// TenantStatus represents the operational status of a tenant
type TenantStatus string

const (
	// TenantStatusActive indicates the tenant is active and operational
	TenantStatusActive TenantStatus = "active"

	// TenantStatusSuspended indicates the tenant is temporarily suspended
	TenantStatusSuspended TenantStatus = "suspended"

	// TenantStatusDeleted indicates the tenant has been marked for deletion
	TenantStatusDeleted TenantStatus = "deleted"
)

// ================================================================================
// JWT Claim Keys
// ================================================================================

const (
	// ClaimKeyIssuer is the standard "iss" claim
	ClaimKeyIssuer = "iss"

	// ClaimKeySubject is the standard "sub" claim
	ClaimKeySubject = "sub"

	// ClaimKeyAudience is the standard "aud" claim
	ClaimKeyAudience = "aud"

	// ClaimKeyExpiresAt is the standard "exp" claim
	ClaimKeyExpiresAt = "exp"

	// ClaimKeyNotBefore is the standard "nbf" claim
	ClaimKeyNotBefore = "nbf"

	// ClaimKeyIssuedAt is the standard "iat" claim
	ClaimKeyIssuedAt = "iat"

	// ClaimKeyJWTID is the standard "jti" claim
	ClaimKeyJWTID = "jti"

	// ClaimKeyTenantID is the custom "tenant_id" claim
	ClaimKeyTenantID = "tenant_id"

	// ClaimKeyAgentID is the custom "agent_id" claim
	ClaimKeyAgentID = "agent_id"

	// ClaimKeyScope is the custom "scope" claim
	ClaimKeyScope = "scope"

	// ClaimKeyTokenType is the custom "type" claim
	ClaimKeyTokenType = "type"

	// ClaimKeyDeviceTrustLevel is the custom "device_trust_level" claim
	ClaimKeyDeviceTrustLevel = "device_trust_level"

	// ClaimKeyAuthorizedParty is the standard "azp" claim
	ClaimKeyAuthorizedParty = "azp"
)

// ================================================================================
// Service Configuration Constants
// ================================================================================

const (
	// DefaultServicePort is the default HTTP service port
	DefaultServicePort = 8080

	// DefaultMetricsPort is the default Prometheus metrics port
	DefaultMetricsPort = 9090

	// DefaultGRPCPort is the default gRPC service port
	DefaultGRPCPort = 50051

	// DefaultHealthCheckPath is the health check endpoint path
	DefaultHealthCheckPath = "/health"

	// DefaultReadinessCheckPath is the readiness check endpoint path
	DefaultReadinessCheckPath = "/health/ready"

	// DefaultLivenessCheckPath is the liveness check endpoint path
	DefaultLivenessCheckPath = "/health/live"

	// DefaultRequestTimeout is the default request timeout (5 seconds)
	DefaultRequestTimeout = 5 * time.Second

	// DefaultShutdownTimeout is the graceful shutdown timeout (30 seconds)
	DefaultShutdownTimeout = 30 * time.Second
)

// ================================================================================
// Logging Constants
// ================================================================================

// LogLevel represents the severity level of log messages
type LogLevel string

const (
	// LogLevelDebug is the most verbose logging level
	LogLevelDebug LogLevel = "debug"

	// LogLevelInfo is the standard informational logging level
	LogLevelInfo LogLevel = "info"

	// LogLevelWarn indicates potential issues
	LogLevelWarn LogLevel = "warn"

	// LogLevelError indicates errors that need attention
	LogLevelError LogLevel = "error"

	// LogLevelFatal indicates critical errors that cause service termination
	LogLevelFatal LogLevel = "fatal"
)

// ================================================================================
// Context Keys
// ================================================================================

// ContextKey represents keys used in context.Context
type ContextKey string

const (
	// ContextKeyRequestID is the key for request ID in context
	ContextKeyRequestID ContextKey = "request_id"

	// ContextKeyTraceID is the key for distributed trace ID in context
	ContextKeyTraceID ContextKey = "trace_id"

	// ContextKeySpanID is the key for trace span ID in context
	ContextKeySpanID ContextKey = "span_id"

	// ContextKeyTenantID is the key for tenant ID in context
	ContextKeyTenantID ContextKey = "tenant_id"

	// ContextKeyAgentID is the key for agent ID in context
	ContextKeyAgentID ContextKey = "agent_id"

	// ContextKeyUserAgent is the key for HTTP User-Agent in context
	ContextKeyUserAgent ContextKey = "user_agent"

	// ContextKeyClientIP is the key for client IP address in context
	ContextKeyClientIP ContextKey = "client_ip"
)

// ================================================================================
// Scope Constants
// ================================================================================

// Scope represents OAuth 2.0 permission scopes
type Scope string

const (
	// ScopeAgentRead allows reading agent information
	ScopeAgentRead Scope = "agent:read"

	// ScopeAgentWrite allows modifying agent information
	ScopeAgentWrite Scope = "agent:write"

	// ScopeIntelligenceQuery allows querying intelligence services
	ScopeIntelligenceQuery Scope = "intelligence:query"

	// ScopeIntelligenceReport allows reporting intelligence data
	ScopeIntelligenceReport Scope = "intelligence:report"

	// ScopeAdminManage allows administrative operations
	ScopeAdminManage Scope = "admin:manage"
)

// DefaultAgentScopes is the default scope granted to agent tokens
var DefaultAgentScopes = []Scope{
	ScopeAgentRead,
	ScopeAgentWrite,
	ScopeIntelligenceQuery,
}

//Personal.AI order the ending
