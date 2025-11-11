// Package models defines the domain models for the CBC authentication service.
// This file contains the Device domain model with business logic.
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/turtacn/cbc/pkg/constants"
)

// Device represents a registered device within the authentication system.
// It holds identification, metadata, and status information crucial for security and management.
// Device 代表认证系统中已注册的设备。
// 它包含对安全和管理至关重要的身份、元数据和状态信息。
type Device struct {
	// DeviceID is the unique identifier for the device.
	// DeviceID 是设备的唯一标识符。
	DeviceID string `json:"device_id" db:"device_id"`

	// TenantID identifies which tenant this device belongs to.
	// TenantID 标识此设备所属的租户。
	TenantID string `json:"tenant_id" db:"tenant_id"`

	// DeviceType indicates the type of device (e.g., mobile, desktop, iot).
	// DeviceType 表示设备类型（例如，移动设备、桌面设备、物联网设备）。
	DeviceType constants.DeviceType `json:"device_type" db:"device_type"`

	// OS is the operating system of the device (e.g., "Windows", "Linux", "macOS").
	// OS 是设备的操作系统（例如，“Windows”、“Linux”、“macOS”）。
	OS string `json:"os" db:"os"`

	// OSVersion is the version of the operating system.
	// OSVersion 是操作系统的版本。
	OSVersion string `json:"os_version" db:"os_version"`

	// AppVersion is the version of the client application running on the device.
	// AppVersion 是设备上运行的客户端应用程序的版本。
	AppVersion string `json:"app_version" db:"app_version"`

	// DeviceName is a user-friendly, mutable name for the device.
	// DeviceName 是用户友好的、可变的设备名称。
	DeviceName string `json:"device_name,omitempty" db:"device_name"`

	// DisplayName is another user-friendly name for the device.
	// DisplayName 是设备的另一个用户友好名称。
	DisplayName string `json:"display_name,omitempty" db:"display_name"`

	// Platform describes the hardware or OS platform (e.g., "x86_64").
	// Platform 描述硬件或操作系统平台（例如，“x86_64”）。
	Platform string `json:"platform,omitempty" db:"platform"`

	// AgentVersion is the version of the CBC agent software.
	// AgentVersion 是 CBC 代理软件的版本。
	AgentVersion string `json:"agent_version,omitempty" db:"agent_version"`

	// DeviceFingerprint is a unique hash generated from stable device characteristics to identify it.
	// DeviceFingerprint 是根据稳定的设备特征生成的唯一哈希值，用于识别设备。
	DeviceFingerprint string `json:"device_fingerprint" db:"device_fingerprint"`

	// TrustLevel indicates the security posture of the device (e.g., high, medium, low).
	// TrustLevel 表示设备的安全状况（例如，高、中、低）。
	TrustLevel constants.TrustLevel `json:"trust_level" db:"trust_level"`

	// Status indicates the current lifecycle status of the device (e.g., active, suspended, revoked).
	// Status 表示设备当前的生命周期状态（例如，活动、暂停、已撤销）。
	Status constants.DeviceStatus `json:"status" db:"status"`

	// RegisteredAt is the timestamp when the device was first registered in the system.
	// RegisteredAt 是设备首次在系统中注册的时间戳。
	RegisteredAt time.Time `json:"registered_at" db:"registered_at"`

	// LastSeenAt is the timestamp of the last authenticated activity from this device.
	// LastSeenAt 是此设备最后一次经认证活动的时间戳。
	LastSeenAt time.Time `json:"last_seen_at" db:"last_seen_at"`

	// LastIPAddress is the last known IP address from which the device connected.
	// LastIPAddress 是设备最后连接的已知 IP 地址。
	LastIPAddress string `json:"last_ip_address,omitempty" db:"last_ip_address"`

	// HardwareInfo contains additional hardware details (e.g., CPU, MAC address) as a string.
	// HardwareInfo 包含额外的硬件详细信息（例如，CPU、MAC 地址）作为字符串。
	HardwareInfo string `json:"hardware_info,omitempty" db:"hardware_info"`

	// CreatedAt is the timestamp when the database record for this device was created.
	// CreatedAt 是创建此设备数据库记录的时间戳。
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt is the timestamp when the database record for this device was last updated.
	// UpdatedAt 是此设备数据库记录最后更新的时间戳。
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// NewDevice creates a new Device instance with sensible defaults.
// It automatically sets timestamps and assigns a default trust level and active status.
// NewDevice 使用合理的默认值创建一个新的 Device 实例。
// 它会自动设置时间戳并分配默认的信任级别和活动状态。
//
// Parameters:
//   - deviceID: The unique identifier for the device.
//   - tenantID: The identifier of the tenant this device belongs to.
//   - deviceType: The type of the device.
//   - os: The operating system of the device.
//   - osVersion: The version of the operating system.
//   - appVersion: The version of the client application.
//
// Returns:
//   - *Device: A pointer to the newly created Device instance.
func NewDevice(deviceID, tenantID string, deviceType constants.DeviceType, os, osVersion, appVersion string) *Device {
	now := time.Now().UTC()
	return &Device{
		DeviceID:     deviceID,
		TenantID:     tenantID,
		DeviceType:   deviceType,
		OS:           os,
		OSVersion:    osVersion,
		AppVersion:   appVersion,
		TrustLevel:   constants.TrustLevelMedium, // Default trust level
		Status:       constants.DeviceStatusActive,
		RegisteredAt: now,
		LastSeenAt:   now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// GenerateFingerprint computes and sets a unique fingerprint for the device.
// The fingerprint is a SHA256 hash of combined device characteristics.
// GenerateFingerprint 计算并设置设备的唯一指纹。
// 指纹是组合设备特征的 SHA256 哈希值。
//
// Returns:
//   - string: The generated hex-encoded fingerprint.
func (d *Device) GenerateFingerprint() string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		d.DeviceID,
		d.DeviceType,
		d.OS,
		d.OSVersion,
		d.AppVersion,
		d.HardwareInfo,
	)
	hash := sha256.Sum256([]byte(data))
	fingerprint := hex.EncodeToString(hash[:])
	d.DeviceFingerprint = fingerprint
	return fingerprint
}

// ValidateFingerprint checks if the provided fingerprint matches the device's stored fingerprint.
// It performs a case-insensitive comparison. If no fingerprint is set on the device, it generates one first.
// ValidateFingerprint 检查提供的指纹是否与设备存储的指纹匹配。
// 它执行不区分大小写的比较。如果设备上没有设置指纹，它会首先生成一个。
//
// Parameters:
//   - fingerprint: The fingerprint to validate.
//
// Returns:
//   - bool: True if the fingerprints match, otherwise false.
func (d *Device) ValidateFingerprint(fingerprint string) bool {
	if d.DeviceFingerprint == "" {
		d.GenerateFingerprint()
	}
	return strings.EqualFold(d.DeviceFingerprint, fingerprint)
}

// IsActive checks if the device's status is 'active'.
// IsActive 检查设备状态是否为“活动”。
//
// Returns:
//   - bool: True if the device is active, otherwise false.
func (d *Device) IsActive() bool {
	return d.Status == constants.DeviceStatusActive
}

// IsSuspended checks if the device's status is 'suspended'.
// IsSuspended 检查设备状态是否为“暂停”。
//
// Returns:
//   - bool: True if the device is suspended, otherwise false.
func (d *Device) IsSuspended() bool {
	return d.Status == constants.DeviceStatusSuspended
}

// IsRevoked checks if the device's status is 'revoked'.
// IsRevoked 检查设备状态是否为“已撤销”。
//
// Returns:
//   - bool: True if the device is revoked, otherwise false.
func (d *Device) IsRevoked() bool {
	return d.Status == constants.DeviceStatusRevoked
}

// CanAuthenticate determines if a device is allowed to authenticate.
// A device can authenticate only if it is active and has a trust level other than 'none'.
// CanAuthenticate 确定是否允许设备进行身份验证。
// 设备只有在活动状态且信任级别不为“无”时才能进行身份验证。
//
// Returns:
//   - bool: True if the device can authenticate, otherwise false.
func (d *Device) CanAuthenticate() bool {
	return d.IsActive() && d.TrustLevel != constants.TrustLevelNone
}

// UpdateLastSeen updates the LastSeenAt timestamp and optionally the LastIPAddress.
// This should be called on every authenticated action to keep the device's activity log current.
// UpdateLastSeen 更新 LastSeenAt 时间戳，并可选择更新 LastIPAddress。
// 每次认证操作都应调用此方法，以保持设备的活动日志最新。
//
// Parameters:
//   - ipAddress: The IP address from the current request.
func (d *Device) UpdateLastSeen(ipAddress string) {
	now := time.Now().UTC()
	d.LastSeenAt = now
	d.UpdatedAt = now
	if ipAddress != "" {
		d.LastIPAddress = ipAddress
	}
}

// Suspend changes the device's status to 'suspended'.
// Suspended devices cannot authenticate but can be reactivated.
// Suspend 将设备状态更改为“暂停”。
// 暂停的设备无法进行身份验证，但可以重新激活。
func (d *Device) Suspend() {
	d.Status = constants.DeviceStatusSuspended
	d.UpdatedAt = time.Now().UTC()
}

// Activate changes the device's status to 'active'.
// This can be used to reactivate a previously suspended device.
// Activate 将设备状态更改为“活动”。
// 这可用于重新激活先前暂停的设备。
func (d *Device) Activate() {
	d.Status = constants.DeviceStatusActive
	d.UpdatedAt = time.Now().UTC()
}

// Revoke changes the device's status to 'revoked'.
// This action is permanent and prevents the device from ever authenticating again.
// Revoke 将设备状态更改为“已撤销”。
// 此操作是永久性的，可防止设备再次进行身份验证。
func (d *Device) Revoke() {
	d.Status = constants.DeviceStatusRevoked
	d.UpdatedAt = time.Now().UTC()
}

// SetTrustLevel updates the device's trust level.
// This is used for risk-based authentication and policy decisions.
// SetTrustLevel 更新设备的信任级别。
// 这用于基于风险的身份验证和策略决策。
//
// Parameters:
//   - level: The new trust level to set.
func (d *Device) SetTrustLevel(level constants.TrustLevel) {
	d.TrustLevel = level
	d.UpdatedAt = time.Now().UTC()
}

// IsInactive checks if the device has been inactive for a given duration.
// IsInactive 检查设备是否在给定时间内处于非活动状态。
//
// Parameters:
//   - duration: The threshold duration to check against.
//
// Returns:
//   - bool: True if the time since LastSeenAt is greater than the duration.
func (d *Device) IsInactive(duration time.Duration) bool {
	return time.Since(d.LastSeenAt) > duration
}

// GetDaysSinceRegistration calculates the number of days that have passed since the device was registered.
// GetDaysSinceRegistration 计算自设备注册以来经过的天数。
//
// Returns:
//   - int: The total number of days since registration.
func (d *Device) GetDaysSinceRegistration() int {
	return int(time.Since(d.RegisteredAt).Hours() / 24)
}

// GetDaysSinceLastSeen calculates the number of days that have passed since the device was last seen.
// GetDaysSinceLastSeen 计算自上次看到设备以来经过的天数。
//
// Returns:
//   - int: The total number of days since the last activity.
func (d *Device) GetDaysSinceLastSeen() int {
	return int(time.Since(d.LastSeenAt).Hours() / 24)
}

// NeedsReAuthentication determines if a device should be forced to re-authenticate based on its inactivity period and trust level.
// Higher trust levels allow for longer periods of inactivity before re-authentication is required.
// NeedsReAuthentication 根据设备的不活动时间和信任级别确定是否应强制设备重新进行身份验证。
// 较高的信任级别允许在需要重新身份验证之前有更长的不活动时间。
//
// Returns:
//   - bool: True if re-authentication is required, otherwise false.
func (d *Device) NeedsReAuthentication() bool {
	var maxInactiveDays int
	switch d.TrustLevel {
	case constants.TrustLevelHigh:
		maxInactiveDays = 30
	case constants.TrustLevelMedium:
		maxInactiveDays = 14
	case constants.TrustLevelLow:
		maxInactiveDays = 7
	default:
		return true // Unknown trust level, require re-auth
	}
	return d.GetDaysSinceLastSeen() > maxInactiveDays
}

// UpdateHardwareInfo updates the device's hardware information and regenerates its fingerprint.
// This is important when hardware changes are detected.
// UpdateHardwareInfo 更新设备的硬件信息并重新生成其指纹。
// 当检测到硬件更改时，这很重要。
//
// Parameters:
//   - hwInfo: The new hardware information string.
func (d *Device) UpdateHardwareInfo(hwInfo string) {
	d.HardwareInfo = hwInfo
	d.UpdatedAt = time.Now().UTC()
	d.GenerateFingerprint()
}

// ToMap converts the Device struct to a map[string]interface{} for flexible serialization.
// It includes both raw field values and calculated properties like 'is_active'.
// ToMap 将 Device 结构体转换为 map[string]interface{} 以实现灵活的序列化。
// 它包括原始字段值和计算属性，如 'is_active'。
//
// Returns:
//   - map[string]interface{}: A map representation of the device.
func (d *Device) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"device_id":          d.DeviceID,
		"tenant_id":          d.TenantID,
		"device_type":        string(d.DeviceType),
		"os":                 d.OS,
		"os_version":         d.OSVersion,
		"app_version":        d.AppVersion,
		"device_name":        d.DeviceName,
		"device_fingerprint": d.DeviceFingerprint,
		"trust_level":        string(d.TrustLevel),
		"status":             string(d.Status),
		"registered_at":      d.RegisteredAt.Unix(),
		"last_seen_at":       d.LastSeenAt.Unix(),
		"last_ip_address":    d.LastIPAddress,
		"hardware_info":      d.HardwareInfo,
		"created_at":         d.CreatedAt.Unix(),
		"updated_at":         d.UpdatedAt.Unix(),
		"is_active":          d.IsActive(),
		"can_authenticate":   d.CanAuthenticate(),
		"days_since_reg":     d.GetDaysSinceRegistration(),
		"days_since_seen":    d.GetDaysSinceLastSeen(),
	}
}

// Clone creates a deep copy of the Device object.
// This is useful to avoid modifying the original object when making changes.
// Clone 创建 Device 对象的深层副本。
// 这在进行更改时避免修改原始对象很有用。
//
// Returns:
//   - *Device: A pointer to the new, cloned Device instance.
func (d *Device) Clone() *Device {
	clone := *d
	return &clone
}
