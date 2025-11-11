// Package models defines the domain models for the CBC authentication service.
// This file contains the Tenant domain model with business logic.
package models

import (
	"encoding/json"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// Tenant represents a tenant organization in the multi-tenant authentication system.
// Each tenant has its own isolated configuration, policies, and cryptographic keys.
// Tenant 代表多租户认证系统中的一个租户组织。
// 每个租户都有自己隔离的配置、策略和加密密钥。
type Tenant struct {
	// TenantID is the unique identifier for the tenant.
	// TenantID 是租户的唯一标识符。
	TenantID string `json:"tenant_id" db:"tenant_id"`

	// TenantName is the display name of the tenant organization.
	// TenantName 是租户组织的显示名称。
	TenantName string `json:"tenant_name" db:"tenant_name"`

	// ComplianceClass specifies a set of compliance-related policies for the tenant (e.g., "FIPS").
	// ComplianceClass 为租户指定一组与合规性相关的策略（例如，“FIPS”）。
	ComplianceClass string `json:"compliance_class" db:"compliance_class"`

	// Status indicates the current status of the tenant (e.g., active, suspended, deleted).
	// Status 指示租户的当前状态（例如，活动、暂停、已删除）。
	Status constants.TenantStatus `json:"status" db:"status"`

	// KeyRotationPolicy defines the configuration for automatic key rotation.
	// KeyRotationPolicy 定义自动密钥轮换的配置。
	KeyRotationPolicy KeyRotationPolicy `json:"key_rotation_policy" db:"key_rotation_policy"`

	// RateLimitConfig defines the rate limiting rules for the tenant.
	// RateLimitConfig 定义租户的速率限制规则。
	RateLimitConfig RateLimitConfig `json:"rate_limit_config" db:"rate_limit_config"`

	// TokenTTLConfig defines the time-to-live settings for tokens issued to the tenant.
	// TokenTTLConfig 定义颁发给租户的令牌的生存时间设置。
	TokenTTLConfig TokenTTLConfig `json:"token_ttl_config" db:"token_ttl_config"`

	// SecurityPolicy defines additional security requirements for the tenant.
	// SecurityPolicy 定义租户的附加安全要求。
	SecurityPolicy SecurityPolicy `json:"security_policy" db:"security_policy"`

	// CreatedAt is the timestamp when the tenant was created.
	// CreatedAt 是创建租户时的时间戳。
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the timestamp of the last update to the tenant's configuration.
	// UpdatedAt 是租户配置最后更新的时间戳。
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// DeletedAt is the timestamp when the tenant was soft-deleted. A non-nil value indicates the tenant is deleted.
	// DeletedAt 是租户被软删除时的时间戳。非 nil 值表示租户已被删除。
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// KeyRotationPolicy defines the key rotation configuration for a tenant.
// KeyRotationPolicy 定义租户的密钥轮换配置。
type KeyRotationPolicy struct {
	// ActiveKeyID is the ID of the key currently used for signing new tokens.
	// ActiveKeyID 是当前用于签署新令牌的密钥的 ID。
	ActiveKeyID string `json:"active_key_id"`

	// RotationIntervalDays is the number of days between automatic key rotations.
	// RotationIntervalDays 是自动密钥轮换之间的天数。
	RotationIntervalDays int `json:"rotation_interval_days"`

	// LastRotatedAt is the timestamp of the last key rotation.
	// LastRotatedAt 是上次密钥轮换的时间戳。
	LastRotatedAt time.Time `json:"last_rotated_at"`

	// NextRotationAt is the scheduled timestamp for the next automatic rotation.
	// NextRotationAt 是下一次自动轮换的预定时间戳。
	NextRotationAt time.Time `json:"next_rotation_at"`

	// DeprecatedKeyIDs is a list of old key IDs that are still valid for token verification but not for signing.
	// DeprecatedKeyIDs 是一个旧密钥 ID 列表，这些密钥对于令牌验证仍然有效，但不能用于签名。
	DeprecatedKeyIDs []string `json:"deprecated_key_ids,omitempty"`

	// AutoRotationEnabled indicates whether automatic key rotation is enabled for the tenant.
	// AutoRotationEnabled 指示是否为租户启用了自动密钥轮换。
	AutoRotationEnabled bool `json:"auto_rotation_enabled"`
}

// RateLimitConfig defines the rate limiting configuration for a tenant.
// RateLimitConfig 定义租户的速率限制配置。
type RateLimitConfig struct {
	// GlobalQPS is the maximum number of requests per second allowed for the entire tenant.
	// GlobalQPS 是整个租户允许的每秒最大请求数。
	GlobalQPS int `json:"global_qps"`

	// PerDeviceQPS is the maximum number of requests per second allowed for a single device.
	// PerDeviceQPS 是单个设备允许的每秒最大请求数。
	PerDeviceQPS int `json:"per_device_qps"`

	// PerDevicePerMinute is the maximum number of requests per minute allowed for a single device.
	// PerDevicePerMinute 是单个设备允许的每分钟最大请求数。
	PerDevicePerMinute int `json:"per_device_per_minute"`

	// RequestsPerMinute is the maximum total requests per minute allowed for the tenant.
	// RequestsPerMinute 是租户允许的每分钟最大总请求数。
	RequestsPerMinute int `json:"requests_per_minute"`

	// BurstSize is the maximum number of requests allowed in a single burst.
	// BurstSize 是单个突发中允许的最大请求数。
	BurstSize int `json:"burst_size"`

	// Enabled indicates whether rate limiting is enabled for the tenant.
	// Enabled 指示是否为租户启用了速率限制。
	Enabled bool `json:"enabled"`
}

// TokenTTLConfig defines the Time-To-Live (TTL) configuration for tokens for a tenant.
// TokenTTLConfig 定义租户令牌的生存时间 (TTL) 配置。
type TokenTTLConfig struct {
	// AccessTokenTTLSeconds is the lifetime of access tokens in seconds.
	// AccessTokenTTLSeconds 是访问令牌的生命周期（以秒为单位）。
	AccessTokenTTLSeconds int `json:"access_token_ttl_seconds"`

	// RefreshTokenTTLSeconds is the lifetime of refresh tokens in seconds.
	// RefreshTokenTTLSeconds 是刷新令牌的生命周期（以秒为单位）。
	RefreshTokenTTLSeconds int `json:"refresh_token_ttl_seconds"`

	// OneTimeRefreshToken indicates if refresh tokens are single-use. If true, a new refresh token is issued upon use.
	// OneTimeRefreshToken 指示刷新令牌是否为一次性使用。如果为 true，则在使用时会颁发新的刷新令牌。
	OneTimeRefreshToken bool `json:"one_time_refresh_token"`
}

// SecurityPolicy defines additional, tenant-specific security requirements.
// SecurityPolicy 定义附加的、特定于租户的安全要求。
type SecurityPolicy struct {
	// RequireDeviceFingerprint indicates if device fingerprint validation is mandatory for token requests.
	// RequireDeviceFingerprint 指示令牌请求是否必须进行设备指纹验证。
	RequireDeviceFingerprint bool `json:"require_device_fingerprint"`

	// RequireMTLS indicates if mutual TLS is required for communication.
	// RequireMTLS 指示通信是否需要双向 TLS。
	RequireMTLS bool `json:"require_mtls"`

	// AllowedIPRanges is a list of allowed IP ranges in CIDR notation from which requests are accepted.
	// AllowedIPRanges 是接受请求的允许 IP 范围列表（CIDR 表示法）。
	AllowedIPRanges []string `json:"allowed_ip_ranges,omitempty"`

	// MinTrustLevel is the minimum device trust level required for authentication.
	// MinTrustLevel 是身份验证所需的最低设备信任级别。
	MinTrustLevel constants.TrustLevel `json:"min_trust_level"`

	// MaxDevicesPerTenant is the maximum number of devices that can be registered under this tenant.
	// MaxDevicesPerTenant 是此租户下可以注册的最大设备数。
	MaxDevicesPerTenant int `json:"max_devices_per_tenant"`
}

// NewTenant creates a new Tenant instance with a set of sensible default policies.
// This function should be used to initialize a new tenant before saving it.
// NewTenant 使用一组合理的默认策略创建一个新的 Tenant 实例。
// 此函数应用于在保存新租户之前对其进行初始化。
//
// Parameters:
//   - tenantID: The unique identifier for the new tenant.
//   - tenantName: The display name for the new tenant.
//
// Returns:
//   - *Tenant: A pointer to the newly created Tenant instance with default settings.
func NewTenant(tenantID, tenantName string) *Tenant {
	now := time.Now().UTC()
	return &Tenant{
		TenantID:   tenantID,
		TenantName: tenantName,
		Status:     constants.TenantStatusActive,
		KeyRotationPolicy: KeyRotationPolicy{
			RotationIntervalDays: 90, // Default 90 days
			AutoRotationEnabled:  true,
			LastRotatedAt:        now,
			NextRotationAt:       now.AddDate(0, 0, 90),
		},
		RateLimitConfig: RateLimitConfig{
			GlobalQPS:          100000, // Default 100k QPS
			PerDeviceQPS:       10,
			PerDevicePerMinute: 600,
			BurstSize:          1000,
			Enabled:            true,
		},
		TokenTTLConfig: TokenTTLConfig{
			AccessTokenTTLSeconds:  900,     // 15 minutes
			RefreshTokenTTLSeconds: 2592000, // 30 days
			OneTimeRefreshToken:    true,
		},
		SecurityPolicy: SecurityPolicy{
			RequireDeviceFingerprint: true,
			RequireMTLS:              false,
			MinTrustLevel:            constants.TrustLevelLow,
			MaxDevicesPerTenant:      10000000, // 10 million devices
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// IsActive checks if the tenant's status is 'active' and it has not been soft-deleted.
// IsActive 检查租户的状态是否为“活动”且尚未被软删除。
//
// Returns:
//   - bool: True if the tenant is active, otherwise false.
func (t *Tenant) IsActive() bool {
	return t.Status == constants.TenantStatusActive && t.DeletedAt == nil
}

// IsSuspended checks if the tenant's status is 'suspended'.
// IsSuspended 检查租户的状态是否为“暂停”。
//
// Returns:
//   - bool: True if the tenant is suspended, otherwise false.
func (t *Tenant) IsSuspended() bool {
	return t.Status == constants.TenantStatusSuspended
}

// IsDeleted checks if the tenant has been soft-deleted.
// IsDeleted 检查租户是否已被软删除。
//
// Returns:
//   - bool: True if DeletedAt is not nil, otherwise false.
func (t *Tenant) IsDeleted() bool {
	return t.DeletedAt != nil
}

// GetAccessTokenTTL returns the access token TTL from the tenant's configuration as a time.Duration.
// GetAccessTokenTTL 以 time.Duration 的形式从租户配置中返回访问令牌 TTL。
//
// Returns:
//   - time.Duration: The access token TTL.
func (t *Tenant) GetAccessTokenTTL() time.Duration {
	return time.Duration(t.TokenTTLConfig.AccessTokenTTLSeconds) * time.Second
}

// GetRefreshTokenTTL returns the refresh token TTL from the tenant's configuration as a time.Duration.
// GetRefreshTokenTTL 以 time.Duration 的形式从租户配置中返回刷新令牌 TTL。
//
// Returns:
//   - time.Duration: The refresh token TTL.
func (t *Tenant) GetRefreshTokenTTL() time.Duration {
	return time.Duration(t.TokenTTLConfig.RefreshTokenTTLSeconds) * time.Second
}

// GetRateLimitThreshold returns the appropriate rate limit threshold based on the given scope.
// GetRateLimitThreshold 根据给定的范围返回适当的速率限制阈值。
//
// Parameters:
//   - scope: The scope to get the rate limit for (e.g., "global", "device").
//
// Returns:
//   - int: The configured QPS or requests per minute for that scope.
func (t *Tenant) GetRateLimitThreshold(scope string) int {
	switch scope {
	case "global":
		return t.RateLimitConfig.GlobalQPS
	case "device":
		return t.RateLimitConfig.PerDeviceQPS
	case "device_minute":
		return t.RateLimitConfig.PerDevicePerMinute
	default:
		return t.RateLimitConfig.PerDeviceQPS
	}
}

// NeedsKeyRotation checks if the tenant's signing key is due for rotation based on its policy.
// NeedsKeyRotation 根据其策略检查租户的签名密钥是否需要轮换。
//
// Returns:
//   - bool: True if auto-rotation is enabled and the next rotation time is in the past.
func (t *Tenant) NeedsKeyRotation() bool {
	if !t.KeyRotationPolicy.AutoRotationEnabled {
		return false
	}
	return time.Now().UTC().After(t.KeyRotationPolicy.NextRotationAt)
}

// ScheduleNextKeyRotation calculates and sets the timestamp for the next key rotation.
// It uses the RotationIntervalDays from the policy.
// ScheduleNextKeyRotation 计算并设置下一次密钥轮换的时间戳。
// 它使用策略中的 RotationIntervalDays。
func (t *Tenant) ScheduleNextKeyRotation() {
	now := time.Now().UTC()
	days := t.KeyRotationPolicy.RotationIntervalDays
	if days <= 0 {
		days = 90 // Default to 90 days if not set or invalid
	}
	t.KeyRotationPolicy.NextRotationAt = now.AddDate(0, 0, days)
	t.UpdatedAt = now
}

// UpdateActiveKey sets a new active key for the tenant and handles the rotation logic.
// The previous active key is moved to the deprecated list, and the next rotation is scheduled.
// UpdateActiveKey 为租户设置一个新的活动密钥并处理轮换逻辑。
// 前一个活动密钥被移动到已弃用列表，并安排下一次轮换。
//
// Parameters:
//   - newKeyID: The ID of the new key to be set as active.
func (t *Tenant) UpdateActiveKey(newKeyID string) {
	now := time.Now().UTC()

	// Move current active key to deprecated list if it exists
	if t.KeyRotationPolicy.ActiveKeyID != "" {
		t.KeyRotationPolicy.DeprecatedKeyIDs = append(
			t.KeyRotationPolicy.DeprecatedKeyIDs,
			t.KeyRotationPolicy.ActiveKeyID,
		)
	}

	// Set the new active key and update timestamps
	t.KeyRotationPolicy.ActiveKeyID = newKeyID
	t.KeyRotationPolicy.LastRotatedAt = now

	// Schedule the next rotation
	t.ScheduleNextKeyRotation()

	t.UpdatedAt = now
}

// RemoveDeprecatedKey removes a key ID from the list of deprecated keys.
// This is typically done after a grace period when the key is no longer needed for verification.
// RemoveDeprecatedKey 从已弃用密钥列表中删除一个密钥 ID。
// 这通常在宽限期过后不再需要密钥进行验证时完成。
//
// Parameters:
//   - keyID: The ID of the key to remove.
func (t *Tenant) RemoveDeprecatedKey(keyID string) {
	var filtered []string
	for _, k := range t.KeyRotationPolicy.DeprecatedKeyIDs {
		if k != keyID {
			filtered = append(filtered, k)
		}
	}
	t.KeyRotationPolicy.DeprecatedKeyIDs = filtered
	t.UpdatedAt = time.Now().UTC()
}

// Suspend changes the tenant's status to 'suspended'.
// A suspended tenant cannot issue or validate tokens.
// Suspend 将租户的状态更改为“暂停”。
// 暂停的租户无法颁发或验证令牌。
func (t *Tenant) Suspend() {
	t.Status = constants.TenantStatusSuspended
	t.UpdatedAt = time.Now().UTC()
}

// Activate changes the tenant's status to 'active'.
// This can reactivate a previously suspended tenant.
// Activate 将租户的状态更改为“活动”。
// 这可以重新激活先前暂停的租户。
func (t *Tenant) Activate() {
	t.Status = constants.TenantStatusActive
	t.UpdatedAt = time.Now().UTC()
}

// SoftDelete marks the tenant as deleted by setting the DeletedAt timestamp.
// This is a non-destructive operation.
// SoftDelete 通过设置 DeletedAt 时间戳将租户标记为已删除。
// 这是一个非破坏性操作。
func (t *Tenant) SoftDelete() {
	now := time.Now().UTC()
	t.DeletedAt = &now
	t.Status = constants.TenantStatusDeleted
	t.UpdatedAt = now
}

// ValidateIPAddress checks if a given IP address is permitted by the tenant's security policy.
// Note: This is a placeholder and requires a proper CIDR matching implementation.
// ValidateIPAddress 检查租户的安全策略是否允许给定的 IP 地址。
// 注意：这是一个占位符，需要一个正确的 CIDR 匹配实现。
//
// Parameters:
//   - ipAddr: The IP address to validate.
//
// Returns:
//   - bool: True if the IP is allowed, otherwise false.
func (t *Tenant) ValidateIPAddress(ipAddr string) bool {
	if len(t.SecurityPolicy.AllowedIPRanges) == 0 {
		return true // No IP restrictions means all are allowed
	}

	// TODO: Implement proper CIDR matching logic
	for _, allowedRange := range t.SecurityPolicy.AllowedIPRanges {
		if allowedRange == ipAddr || allowedRange == "0.0.0.0/0" {
			return true
		}
	}

	return false
}

// ValidateTrustLevel checks if a given device trust level meets the tenant's minimum requirement.
// ValidateTrustLevel 检查给定的设备信任级别是否满足租户的最低要求。
//
// Parameters:
//   - deviceTrustLevel: The trust level of the device to check.
//
// Returns:
//   - bool: True if the device's trust level is sufficient, otherwise false.
func (t *Tenant) ValidateTrustLevel(deviceTrustLevel constants.TrustLevel) bool {
	trustLevels := map[constants.TrustLevel]int{
		constants.TrustLevelNone:   0,
		constants.TrustLevelLow:    1,
		constants.TrustLevelMedium: 2,
		constants.TrustLevelHigh:   3,
	}

	deviceLevel, ok := trustLevels[deviceTrustLevel]
	if !ok {
		return false // Unknown trust level is not trusted
	}
	minLevel := trustLevels[t.SecurityPolicy.MinTrustLevel]

	return deviceLevel >= minLevel
}

// ToJSON serializes the Tenant object into a JSON string.
// ToJSON 将 Tenant 对象序列化为 JSON 字符串。
//
// Returns:
//   - string: The JSON representation of the tenant.
//   - error: An error if serialization fails.
func (t *Tenant) ToJSON() (string, error) {
	data, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON deserializes a JSON string into the Tenant object.
// FromJSON 将 JSON 字符串反序列化为 Tenant 对象。
//
// Parameters:
//   - jsonStr: The JSON string to parse.
//
// Returns:
//   - error: An error if deserialization fails.
func (t *Tenant) FromJSON(jsonStr string) error {
	return json.Unmarshal([]byte(jsonStr), t)
}

// ToMap converts the Tenant struct to a map[string]interface{} for flexible serialization.
// It includes calculated properties for convenience.
// ToMap 将 Tenant 结构体转换为 map[string]interface{} 以实现灵活的序列化。
// 为方便起见，它包括了计算属性。
//
// Returns:
//   - map[string]interface{}: A map representation of the tenant.
func (t *Tenant) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"tenant_id":            t.TenantID,
		"tenant_name":          t.TenantName,
		"status":               string(t.Status),
		"key_rotation_policy":  t.KeyRotationPolicy,
		"rate_limit_config":    t.RateLimitConfig,
		"token_ttl_config":     t.TokenTTLConfig,
		"security_policy":      t.SecurityPolicy,
		"created_at":           t.CreatedAt.Unix(),
		"updated_at":           t.UpdatedAt.Unix(),
		"is_active":            t.IsActive(),
		"needs_key_rotation":   t.NeedsKeyRotation(),
		"access_token_ttl_min": t.TokenTTLConfig.AccessTokenTTLSeconds / 60,
		"refresh_token_ttl_days": t.TokenTTLConfig.RefreshTokenTTLSeconds / 86400,
	}

	if t.DeletedAt != nil {
		m["deleted_at"] = t.DeletedAt.Unix()
	}

	return m
}

// Clone creates a deep copy of the Tenant object.
// This is important to avoid race conditions when modifying tenant policies in concurrent requests.
// Clone 创建 Tenant 对象的深层副本。
// 这对于避免在并发请求中修改租户策略时的竞争条件很重要。
//
// Returns:
//   - *Tenant: A pointer to the new, cloned Tenant instance.
func (t *Tenant) Clone() *Tenant {
	clone := *t

	// Deep copy slices to avoid modifying the original
	if len(t.KeyRotationPolicy.DeprecatedKeyIDs) > 0 {
		clone.KeyRotationPolicy.DeprecatedKeyIDs = make([]string, len(t.KeyRotationPolicy.DeprecatedKeyIDs))
		copy(clone.KeyRotationPolicy.DeprecatedKeyIDs, t.KeyRotationPolicy.DeprecatedKeyIDs)
	}

	if len(t.SecurityPolicy.AllowedIPRanges) > 0 {
		clone.SecurityPolicy.AllowedIPRanges = make([]string, len(t.SecurityPolicy.AllowedIPRanges))
		copy(clone.SecurityPolicy.AllowedIPRanges, t.SecurityPolicy.AllowedIPRanges)
	}

	return &clone
}
