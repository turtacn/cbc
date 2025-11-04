package dto

import (
	"time"
)

// DeviceRegisterRequestV2 设备注册请求 DTO（用于直接设备注册场景）
type DeviceRegisterRequestV2 struct {
	TenantID          string            `json:"tenant_id" validate:"required,min=1,max=64"`
	AgentID           string            `json:"agent_id" validate:"required,min=1,max=128"`
	DeviceFingerprint string            `json:"device_fingerprint" validate:"required,min=1,max=128"`
	DeviceName        string            `json:"device_name" validate:"required,min=1,max=256"`
	DeviceType        string            `json:"device_type" validate:"required,oneof=desktop mobile server iot embedded"`
	OSType            string            `json:"os_type" validate:"omitempty,max=64"`
	OSVersion         string            `json:"os_version" validate:"omitempty,max=64"`
	HardwareInfo      map[string]string `json:"hardware_info" validate:"omitempty"`
	IPAddress         string            `json:"ip_address" validate:"omitempty,ip"`
	UserAgent         string            `json:"user_agent" validate:"omitempty,max=512"`
	Metadata          map[string]string `json:"metadata" validate:"omitempty"`
}

// DeviceUpdateRequest 设备更新请求 DTO
type DeviceUpdateRequest struct {
	TenantID          string            `json:"tenant_id" validate:"required,min=1,max=64"`
	AgentID           string            `json:"agent_id" validate:"required,min=1,max=128"`
	DeviceName        string            `json:"device_name" validate:"omitempty,max=256"`
	DeviceFingerprint string            `json:"device_fingerprint" validate:"omitempty,min=1,max=128"`
	TrustLevel        string            `json:"trust_level" validate:"omitempty,oneof=high medium low untrusted"`
	Status            string            `json:"status" validate:"omitempty,oneof=active inactive suspended"`
	Metadata          map[string]string `json:"metadata" validate:"omitempty"`
}

// DeviceQueryRequest 设备查询请求 DTO
type DeviceQueryRequest struct {
	TenantID   string `json:"tenant_id" validate:"required,min=1,max=64"`
	AgentID    string `json:"agent_id" validate:"omitempty,min=1,max=128"`
	DeviceType string `json:"device_type" validate:"omitempty"`
	TrustLevel string `json:"trust_level" validate:"omitempty,oneof=high medium low untrusted"`
	Status     string `json:"status" validate:"omitempty,oneof=active inactive suspended"`
	Page       int    `json:"page" validate:"omitempty,min=1"`
	PageSize   int    `json:"page_size" validate:"omitempty,min=1,max=100"`
}

// DeviceResponse 设备响应 DTO
type DeviceResponse struct {
	TenantID          string            `json:"tenant_id"`
	AgentID           string            `json:"agent_id"`
	DeviceID          string            `json:"device_id"`
	DeviceName        string            `json:"device_name"`
	DeviceType        string            `json:"device_type"`
	DeviceFingerprint string            `json:"device_fingerprint"`
	TrustLevel        string            `json:"trust_level"`
	Status            string            `json:"status"`
	OSType            string            `json:"os_type,omitempty"`
	OSVersion         string            `json:"os_version,omitempty"`
	LastSeenAt        time.Time         `json:"last_seen_at"`
	RegisteredAt      time.Time         `json:"registered_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	IPAddress         string            `json:"ip_address,omitempty"`
	UserAgent         string            `json:"user_agent,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	RefreshToken      string            `json:"refresh_token,omitempty"`
}

// DeviceListResponse 设备列表响应 DTO
type DeviceListResponse struct {
	Devices    []DeviceResponse `json:"devices"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

// DeviceTrustScoreRequest 设备信任评分请求 DTO
type DeviceTrustScoreRequest struct {
	TenantID          string            `json:"tenant_id" validate:"required,min=1,max=64"`
	AgentID           string            `json:"agent_id" validate:"required,min=1,max=128"`
	DeviceFingerprint string            `json:"device_fingerprint" validate:"required,min=1,max=128"`
	BehaviorSignals   map[string]string `json:"behavior_signals" validate:"omitempty"`
	ContextSignals    map[string]string `json:"context_signals" validate:"omitempty"`
}

// DeviceTrustScoreResponse 设备信任评分响应 DTO
type DeviceTrustScoreResponse struct {
	TenantID      string            `json:"tenant_id"`
	AgentID       string            `json:"agent_id"`
	TrustScore    float64           `json:"trust_score"`
	TrustLevel    string            `json:"trust_level"`
	RiskFactors   []string          `json:"risk_factors,omitempty"`
	Recommendations []string        `json:"recommendations,omitempty"`
	EvaluatedAt   time.Time         `json:"evaluated_at"`
	Details       map[string]string `json:"details,omitempty"`
}

// DeviceRevokeRequest 设备凭证吊销请求 DTO
type DeviceRevokeRequest struct {
	TenantID string `json:"tenant_id" validate:"required,min=1,max=64"`
	AgentID  string `json:"agent_id" validate:"required,min=1,max=128"`
	Reason   string `json:"reason" validate:"required,min=1,max=256"`
}

// DeviceRevokeResponse 设备凭证吊销响应 DTO
type DeviceRevokeResponse struct {
	Success     bool      `json:"success"`
	TenantID    string    `json:"tenant_id"`
	AgentID     string    `json:"agent_id"`
	RevokedAt   time.Time `json:"revoked_at"`
	TokensRevoked int     `json:"tokens_revoked"`
	Message     string    `json:"message,omitempty"`
}

// NewDeviceResponse 创建设备响应 DTO
func NewDeviceResponse(tenantID, agentID, deviceID, deviceName, deviceType, deviceFingerprint, trustLevel, status string) *DeviceResponse {
	now := time.Now()
	return &DeviceResponse{
		TenantID:          tenantID,
		AgentID:           agentID,
		DeviceID:          deviceID,
		DeviceName:        deviceName,
		DeviceType:        deviceType,
		DeviceFingerprint: deviceFingerprint,
		TrustLevel:        trustLevel,
		Status:            status,
		LastSeenAt:        now,
		RegisteredAt:      now,
		UpdatedAt:         now,
	}
}

// NewDeviceListResponse 创建设备列表响应 DTO
func NewDeviceListResponse(devices []DeviceResponse, total int64, page, pageSize int) *DeviceListResponse {
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}
	return &DeviceListResponse{
		Devices:    devices,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}
}

//Personal.AI order the ending
