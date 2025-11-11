package models

import (
	"time"

	"github.com/google/uuid"
)

// KLREvent represents a Key Lifecycle Report (KLR) event, capturing significant moments in a key's life.
// These events are used for compliance and auditing purposes.
// KLREvent 代表密钥生命周期报告 (KLR) 事件，捕捉密钥生命中的重要时刻。
// 这些事件用于合规性和审计目的。
type KLREvent struct {
	// EventID is the unique identifier for the event.
	// EventID 是事件的唯一标识符。
	EventID uuid.UUID `json:"event_id"`
	// KeyID is the identifier of the key that the event pertains to.
	// KeyID 是事件相关的密钥的标识符。
	KeyID string `json:"key_id"`
	// TenantID is the identifier of the tenant that owns the key.
	// TenantID 是拥有该密钥的租户的标识符。
	TenantID string `json:"tenant_id"`
	// Status is the new status of the key after the event (e.g., "created", "rotated", "revoked").
	// Status 是事件发生后密钥的新状态（例如，“已创建”、“已轮换”、“已撤销”）。
	Status string `json:"status"`
	// EventTimestamp is the time when the event occurred.
	// EventTimestamp 是事件发生的时间。
	EventTimestamp time.Time `json:"event_timestamp"`
	// Metadata contains additional details about the event in a structured format (e.g., JSON).
	// Metadata 包含有关事件的结构化格式（例如 JSON）的附加详细信息。
	Metadata string `json:"metadata"`
	// Version is the version of the key after this event.
	// Version 是此事件后密钥的版本。
	Version int `json:"version"`
}

// PolicyRequest represents a request sent to the policy engine to evaluate a decision.
// It contains contextual information needed for the engine to make a ruling.
// PolicyRequest 代表发送到策略引擎以评估决策的请求。
// 它包含引擎做出裁决所需的上下文信息。
type PolicyRequest struct {
	// ComplianceClass specifies the compliance standard to be evaluated against (e.g., "FIPS-140-2").
	// ComplianceClass 指定要评估的合规标准（例如，“FIPS-140-2”）。
	ComplianceClass string `json:"compliance_class"`
	// KeySize is the size of the cryptographic key in bits.
	// KeySize 是加密密钥的大小（以位为单位）。
	KeySize int `json:"key_size"`
	// CurrentRiskProfile is the current risk profile of the tenant, which may influence the policy decision.
	// CurrentRiskProfile 是租户当前的风险状况，可能会影响策略决策。
	CurrentRiskProfile *TenantRiskProfile `json:"current_risk_profile,omitempty"`
}
