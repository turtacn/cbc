//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/audit"
	"github.com/turtacn/cbc/pkg/logger"
)

func TestAuditKafkaIntegration(t *testing.T) {
	if os.Getenv("SKIP_DOCKER_TESTS") != "" {
		t.Skip("Skipping Docker-dependent tests")
	}
	cfg := config.KafkaConfig{
		Brokers:    []string{kafkaBroker},
		AuditTopic: auditTopic,
	}
	producer, err := audit.NewKafkaProducer(cfg, logger.NewNoopLogger())
	assert.NoError(t, err)

	event := models.AuditEvent{
		EventType: "test.event",
		TenantID:  "test-tenant",
		Success:   true,
	}

	err = producer.LogEvent(context.Background(), event)
	assert.NoError(t, err)

	// Consume the message to verify it was sent
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:   []string{kafkaBroker},
		Topic:     auditTopic,
		Partition: 0,
		MinBytes:  10e3, // 10KB
		MaxBytes:  10e6, // 10MB
	})
	defer r.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msg, err := r.ReadMessage(ctx)
	assert.NoError(t, err)

	var receivedEvent models.AuditEvent
	err = json.Unmarshal(msg.Value, &receivedEvent)
	assert.NoError(t, err)
	assert.Equal(t, event.EventType, receivedEvent.EventType)
	assert.Equal(t, event.TenantID, receivedEvent.TenantID)
}
