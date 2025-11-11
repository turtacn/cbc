package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/turtacn/cbc/internal/domain/models"
)

// SignAuditEvent calculates and returns the HMAC-SHA256 signature for an audit event.
// This is used to ensure the integrity and authenticity of audit logs.
// SignAuditEvent 计算并返回审计事件的 HMAC-SHA256 签名。
// 这用于确保审计日志的完整性和真实性。
func SignAuditEvent(event models.AuditEvent, secretKey string) (string, error) {
	// Serialize the event to JSON
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	// Calculate the HMAC-SHA256 signature
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write(eventBytes)
	signature := h.Sum(nil)

	// Encode the signature in Base64
	return base64.StdEncoding.EncodeToString(signature), nil
}
