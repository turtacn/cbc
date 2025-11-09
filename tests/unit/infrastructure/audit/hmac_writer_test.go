package audit_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/audit"
)

func TestSignAuditEvent(t *testing.T) {
	event := models.AuditEvent{
		ID:        uuid.New(),
		TenantID:  "test-tenant",
		Actor:     "test-actor",
		Action:    "test-action",
		Timestamp: time.Now(),
	}
	secretKey := "test-secret"

	sig, err := audit.SignAuditEvent(event, secretKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, sig)
}
