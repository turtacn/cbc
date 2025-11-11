package models

import "github.com/golang-jwt/jwt/v5"

// Claims represents the custom JWT claims used in the CBC authentication service.
// It embeds the standard jwt.RegisteredClaims and adds custom fields for tenant, device, and scope.
// Claims 代表 CBC 认证服务中使用的自定义 JWT 声明。
// 它嵌入了标准的 jwt.RegisteredClaims，并添加了租户、设备和范围的自定义字段。
type Claims struct {
	jwt.RegisteredClaims
	// TenantID is the identifier of the tenant to whom the token was issued.
	// TenantID 是颁发令牌的租户的标识符。
	TenantID string `json:"tenant_id"`
	// DeviceID is the identifier of the device for which the token was issued.
	// DeviceID 是为其颁发令牌的设备的标识符。
	DeviceID string `json:"device_id"`
	// Scope defines the permissions granted by the token.
	// Scope 定义了令牌授予的权限。
	Scope string `json:"scope"`
	// DeviceTrustLevel is the trust level of the device, if available.
	// DeviceTrustLevel 是设备的信任级别（如果可用）。
	DeviceTrustLevel string `json:"device_trust_level,omitempty"`
}
