package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/turtacn/cbc/internal/domain/models"
)

// SignAuditEvent calculates the HMAC-SHA256 signature for an audit event.
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
