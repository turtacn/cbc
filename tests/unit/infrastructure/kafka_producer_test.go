//go:build unit

package infrastructure_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/audit"
	"github.com/turtacn/cbc/pkg/logger"
)

// MockKafkaWriter is a mock of the Kafka writer
type MockKafkaWriter struct {
	mock.Mock
}

func (m *MockKafkaWriter) WriteMessages(ctx context.Context, msgs ...kafka.Message) error {
	args := m.Called(ctx, msgs)
	return args.Error(0)
}

func (m *MockKafkaWriter) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestKafkaProducer_LogEvent(t *testing.T) {
	mockWriter := new(MockKafkaWriter)
	cfg := config.KafkaConfig{
		Brokers:    []string{"localhost:9092"},
		AuditTopic: "test-audit-topic",
	}

	producer, err := audit.NewKafkaProducer(cfg, logger.NewNoopLogger())
	assert.NoError(t, err)

	// Replace the real writer with the mock
	// This is a bit of a hack, a better way would be to make the writer an interface
	// and inject the mock. For this test, we'll use this approach.
	type kafkaProducer struct {
		writer *kafka.Writer
		logger logger.Logger
	}
	producer.(*audit.KafkaProducer).writer = (*kafka.Writer)(mockWriter)

	event := models.AuditEvent{
		EventType: "test.event",
		TenantID:  "test-tenant",
		Success:   true,
	}
	eventBytes, _ := json.Marshal(event)

	mockWriter.On("WriteMessages", mock.Anything, []kafka.Message{{Value: eventBytes}}).Return(nil)

	err = producer.LogEvent(context.Background(), event)
	assert.NoError(t, err)

	mockWriter.AssertExpectations(t)
}
