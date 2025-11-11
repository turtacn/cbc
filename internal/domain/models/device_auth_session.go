// Package models defines the domain models.
package models

import "time"

// DeviceAuthStatus represents the status of a device authorization request in the OAuth 2.0 Device Flow.
// DeviceAuthStatus 表示 OAuth 2.0 设备流程中设备授权请求的状态。
type DeviceAuthStatus string

const (
	// DeviceAuthStatusPending indicates that the user has not yet approved or denied the request.
	// DeviceAuthStatusPending 表示用户尚未批准或拒绝该请求。
	DeviceAuthStatusPending DeviceAuthStatus = "pending"
	// DeviceAuthStatusApproved indicates that the user has approved the request.
	// DeviceAuthStatusApproved 表示用户已批准该请求。
	DeviceAuthStatusApproved DeviceAuthStatus = "approved"
	// DeviceAuthStatusDenied indicates that the user has denied the request.
	// DeviceAuthStatusDenied 表示用户已拒绝该请求。
	DeviceAuthStatusDenied DeviceAuthStatus = "denied"
)

// DeviceAuthSession represents the state of a single OAuth 2.0 Device Authorization Grant flow.
// It stores all the necessary information to manage the session from initiation to completion.
// DeviceAuthSession 代表单个 OAuth 2.0 设备授权授予流程的状态。
// 它存储了从启动到完成管理会话所需的所有必要信息。
type DeviceAuthSession struct {
	// DeviceCode is the long, secret code that the device uses to poll for the token.
	// DeviceCode 是设备用于轮询令牌的长密钥。
	DeviceCode string
	// UserCode is the short, user-friendly code that the user enters on a secondary device to authorize the request.
	// UserCode 是用户在辅助设备上输入以授权请求的简短、用户友好的代码。
	UserCode string
	// ClientID is the identifier of the client application that initiated the authorization flow.
	// ClientID 是发起授权流程的客户端应用程序的标识符。
	ClientID string
	// Scope is the requested scope of access for the token.
	// Scope 是令牌请求的访问范围。
	Scope string
	// Status is the current status of the authorization request (pending, approved, or denied).
	// Status 是授权请求的当前状态（待定、已批准或已拒绝）。
	Status DeviceAuthStatus
	// ExpiresAt is the timestamp when the device_code and user_code will expire.
	// ExpiresAt 是 device_code 和 user_code 将过期的时间戳。
	ExpiresAt time.Time
	// Interval is the recommended minimum number of seconds that the device should wait between polling requests.
	// Interval 是设备在轮询请求之间应等待的建议最短秒数。
	Interval int
	// LastPollAt is the timestamp of the most recent polling request from the device.
	// LastPollAt 是来自设备的最近一次轮询请求的时间戳。
	LastPollAt time.Time
	// TenantID is the identifier of the tenant in which the authorization is taking place.
	// TenantID 是授权所在的租户的标识符。
	TenantID string
	// Subject is the identifier of the user who authorized the request. It is populated once the status is 'approved'.
	// Subject 是授权请求的用户的标识符。一旦状态为“已批准”，该字段将被填充。
	Subject string
}
