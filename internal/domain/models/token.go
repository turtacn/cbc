// Package models defines the domain models for the CBC authentication service.
// This file contains the Token domain model with business logic.
package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/pkg/constants"
)

// Token represents a JWT in the authentication system, encapsulating all necessary information
// for its lifecycle management, from issuance to revocation and verification.
// Token 代表认证系统中的 JWT，封装了其生命周期管理所需的所有必要信息，
// 从颁发到撤销和验证。
type Token struct {
	// JTI (JWT ID) is the unique identifier for the token, used to prevent replay attacks.
	// JTI (JWT ID) 是令牌的唯一标识符，用于防止重放攻击。
	JTI string `json:"jti" db:"jti"`

	// TenantID identifies the tenant to whom this token belongs.
	// TenantID 标识此令牌所属的租户。
	TenantID string `json:"tenant_id" db:"tenant_id"`

	// DeviceID identifies the device for which this token was issued.
	// DeviceID 标识为其颁发此令牌的设备。
	DeviceID string `json:"device_id" db:"device_id"`

	// TokenType indicates whether this is an "access_token" or "refresh_token".
	// TokenType 指示这是“access_token”还是“refresh_token”。
	TokenType constants.TokenType `json:"token_type" db:"token_type"`

	// Scope defines the permissions granted by this token.
	// Scope 定义此令牌授予的权限。
	Scope string `json:"scope" db:"scope"`

	// IssuedAt is the timestamp when the token was created.
	// IssuedAt 是创建令牌时的时间戳。
	IssuedAt time.Time `json:"issued_at" db:"issued_at"`

	// ExpiresAt is the timestamp when the token will expire.
	// ExpiresAt 是令牌将过期的时间戳。
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`

	// RevokedAt is the timestamp when the token was revoked. A nil value means it has not been revoked.
	// RevokedAt 是令牌被撤销时的时间戳。nil 值表示尚未撤销。
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`

	// DeviceFingerprint is a hash of device characteristics for additional security binding.
	// DeviceFingerprint 是用于额外安全绑定的设备特征哈希。
	DeviceFingerprint string `json:"device_fingerprint,omitempty" db:"device_fingerprint"`

	// IPAddress is the source IP address from which the token was requested.
	// IPAddress 是请求令牌的源 IP 地址。
	IPAddress string `json:"ip_address,omitempty" db:"ip_address"`

	// UserAgent is the user agent string of the client that requested the token.
	// UserAgent 是请求令牌的客户端的用户代理字符串。
	UserAgent string `json:"user_agent,omitempty" db:"user_agent"`

	// CreatedAt is the timestamp when the token record was created in the database.
	// CreatedAt 是在数据库中创建令牌记录时的时间戳。
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the timestamp when the token record was last updated.
	// UpdatedAt 是令牌记录上次更新时的时间戳。
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Metadata is a map for storing additional custom data associated with the token.
	// Metadata 是用于存储与令牌关联的其他自定义数据的映射。
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
}

// NewToken creates a new Token instance with the provided parameters.
// It automatically sets the IssuedAt, CreatedAt, and UpdatedAt fields to the current UTC time.
// NewToken 使用提供的参数创建一个新的 Token 实例。
// 它会自动将 IssuedAt、CreatedAt 和 UpdatedAt 字段设置为当前的 UTC 时间。
//
// Parameters:
//   - jti: The unique JWT ID.
//   - tenantID: The ID of the tenant.
//   - deviceID: The ID of the device.
//   - tokenType: The type of the token (access or refresh).
//   - scope: The permissions scope.
//   - ttl: The time-to-live duration for the token.
//
// Returns:
//   - *Token: A pointer to the newly created Token.
func NewToken(jti, tenantID, deviceID string, tokenType constants.TokenType, scope string, ttl time.Duration) *Token {
	now := time.Now().UTC()
	return &Token{
		JTI:       jti,
		TenantID:  tenantID,
		DeviceID:  deviceID,
		TokenType: tokenType,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// IsExpired checks if the token has expired based on its ExpiresAt timestamp.
// IsExpired 根据其 ExpiresAt 时间戳检查令牌是否已过期。
//
// Returns:
//   - bool: True if the token is expired, otherwise false.
func (t *Token) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}

// IsRevoked checks if the token has been explicitly revoked.
// IsRevoked 检查令牌是否已被明确撤销。
//
// Returns:
//   - bool: True if RevokedAt is not nil, otherwise false.
func (t *Token) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsValid checks if the token is currently valid for use (i.e., not expired and not revoked).
// IsValid 检查令牌当前是否有效（即未过期且未撤销）。
//
// Returns:
//   - bool: True if the token is valid, otherwise false.
func (t *Token) IsValid() bool {
	return !t.IsExpired() && !t.IsRevoked()
}

// CanRefresh determines if a token is a valid refresh token that can be used to obtain new tokens.
// CanRefresh 确定令牌是否是可用于获取新令牌的有效刷新令牌。
//
// Returns:
//   - bool: True if the token is a valid refresh token, otherwise false.
func (t *Token) CanRefresh() bool {
	return t.TokenType == constants.TokenTypeRefresh && t.IsValid()
}

// Revoke marks the token as revoked by setting the RevokedAt timestamp.
// Revoke 通过设置 RevokedAt 时间戳将令牌标记为已撤销。
func (t *Token) Revoke() {
	now := time.Now().UTC()
	t.RevokedAt = &now
	t.UpdatedAt = now
}

// TimeUntilExpiry returns the remaining duration until the token expires.
// It returns 0 if the token is already expired.
// TimeUntilExpiry 返回令牌过期的剩余时间。
// 如果令牌已过期，则返回 0。
//
// Returns:
//   - time.Duration: The remaining time until expiry.
func (t *Token) TimeUntilExpiry() time.Duration {
	if t.IsExpired() {
		return 0
	}
	return time.Until(t.ExpiresAt)
}

// IsAccessToken checks if this token is an access token.
// IsAccessToken 检查此令牌是否为访问令牌。
//
// Returns:
//   - bool: True if the token type is 'access'.
func (t *Token) IsAccessToken() bool {
	return t.TokenType == constants.TokenTypeAccess
}

// IsRefreshToken checks if this token is a refresh token.
// IsRefreshToken 检查此令牌是否为刷新令牌。
//
// Returns:
//   - bool: True if the token type is 'refresh'.
func (t *Token) IsRefreshToken() bool {
	return t.TokenType == constants.TokenTypeRefresh
}

// HasScope checks if the token's scope string contains a specific scope.
// This is a simple substring check and may need to be more robust for complex scope logic.
// HasScope 检查令牌的范围字符串是否包含特定范围。
// 这是一个简单的子字符串检查，对于复杂的范围逻辑可能需要更强大。
//
// Parameters:
//   - scope: The scope to check for.
//
// Returns:
//   - bool: True if the scope is present, otherwise false.
func (t *Token) HasScope(scope string) bool {
	if t.Scope == "" {
		return false
	}
	return contains(t.Scope, scope)
}

// GetRemainingLifetime calculates the remaining lifetime of the token as a percentage.
// GetRemainingLifetime 以百分比形式计算令牌的剩余生命周期。
//
// Returns:
//   - float64: The remaining lifetime percentage (0-100). Returns 0 if expired.
func (t *Token) GetRemainingLifetime() float64 {
	if t.IsExpired() {
		return 0
	}
	totalLifetime := t.ExpiresAt.Sub(t.IssuedAt).Seconds()
	if totalLifetime <= 0 {
		return 0
	}
	elapsed := time.Now().UTC().Sub(t.IssuedAt).Seconds()
	remaining := ((totalLifetime - elapsed) / totalLifetime) * 100
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ShouldRotate determines if a refresh token should be rotated based on its age.
// The current policy is to rotate if less than 50% of its lifetime remains.
// ShouldRotate 根据刷新令牌的年龄确定是否应轮换刷新令牌。
// 当前策略是如果剩余生命周期少于 50%，则进行轮换。
//
// Returns:
//   - bool: True if the token is a refresh token and should be rotated.
func (t *Token) ShouldRotate() bool {
	if !t.IsRefreshToken() {
		return false
	}
	return t.GetRemainingLifetime() < 50
}

// ValidateDeviceFingerprint checks if the provided fingerprint matches the one bound to the token.
// This helps mitigate token theft.
// ValidateDeviceFingerprint 检查提供的指纹是否与绑定到令牌的指纹匹配。
// 这有助于减轻令牌被盗的风险。
//
// Parameters:
//   - fingerprint: The device fingerprint to validate.
//
// Returns:
//   - bool: True if the fingerprint matches or if no fingerprint is required.
func (t *Token) ValidateDeviceFingerprint(fingerprint string) bool {
	if t.DeviceFingerprint == "" {
		return true // No fingerprint validation required for this token
	}
	return t.DeviceFingerprint == fingerprint
}

// ToMap converts the Token struct to a map[string]interface{} for flexible serialization.
// ToMap 将 Token 结构体转换为 map[string]interface{} 以实现灵活的序列化。
//
// Returns:
//   - map[string]interface{}: A map representation of the token.
func (t *Token) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"jti":         t.JTI,
		"tenant_id":   t.TenantID,
		"device_id":   t.DeviceID,
		"token_type":  string(t.TokenType),
		"scope":       t.Scope,
		"issued_at":   t.IssuedAt.Unix(),
		"expires_at":  t.ExpiresAt.Unix(),
		"created_at":  t.CreatedAt.Unix(),
		"updated_at":  t.UpdatedAt.Unix(),
		"is_expired":  t.IsExpired(),
		"is_revoked":  t.IsRevoked(),
	}

	if t.RevokedAt != nil {
		m["revoked_at"] = t.RevokedAt.Unix()
	}
	if t.DeviceFingerprint != "" {
		m["device_fingerprint"] = t.DeviceFingerprint
	}
	if t.IPAddress != "" {
		m["ip_address"] = t.IPAddress
	}
	if t.UserAgent != "" {
		m["user_agent"] = t.UserAgent
	}
	return m
}

// contains is a helper function to check for the presence of a scope in a space-delimited string.
// contains 是一个辅助函数，用于检查以空格分隔的字符串中是否存在范围。
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)+1] == substr+" " ||
			s[len(s)-len(substr)-1:] == " "+substr ||
			len(s) > len(substr)*2 && findInMiddle(s, substr))))
}

// findInMiddle is a helper for 'contains' to find a substring surrounded by spaces.
// findInMiddle 是“contains”的辅助函数，用于查找被空格包围的子字符串。
func findInMiddle(s, substr string) bool {
	target := " " + substr + " "
	for i := 0; i <= len(s)-len(target); i++ {
		if s[i:i+len(target)] == target {
			return true
		}
	}
	return false
}

// ToClaims converts the Token model to a standard JWT Claims object for signing.
// ToClaims 将 Token 模型转换为用于签名的标准 JWT Claims 对象。
//
// Returns:
//   - jwt.Claims: The populated claims object.
func (t *Token) ToClaims() jwt.Claims {
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        t.JTI,
			Subject:   t.DeviceID,
			Audience:  jwt.ClaimStrings{"api"},
			ExpiresAt: jwt.NewNumericDate(t.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(t.IssuedAt),
			NotBefore: jwt.NewNumericDate(t.IssuedAt),
		},
		TenantID: t.TenantID,
		DeviceID: t.DeviceID,
		Scope:    t.Scope,
	}
}

// TokenIntrospection represents the response structure for an RFC 7662 token introspection endpoint.
// TokenIntrospection 代表 RFC 7662 令牌自省端点的响应结构。
type TokenIntrospection struct {
	Active    bool                   `json:"active"`
	Scope     string                 `json:"scope,omitempty"`
	ClientID  string                 `json:"client_id,omitempty"`
	Username  string                 `json:"username,omitempty"`
	TokenType string                 `json:"token_type,omitempty"`
	Exp       int64                  `json:"exp,omitempty"`
	Iat       int64                  `json:"iat,omitempty"`
	Nbf       int64                  `json:"nbf,omitempty"`
	Sub       string                 `json:"sub,omitempty"`
	Aud       []string               `json:"aud,omitempty"`
	Iss       string                 `json:"iss,omitempty"`
	Jti       string                 `json:"jti,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}
