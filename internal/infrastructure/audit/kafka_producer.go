// Package audit implements the AuditService interface using Kafka.
package audit

import (
	"context"
	"encoding/json"

	"github.com/segmentio/kafka-go"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// KafkaProducer is a Kafka-backed implementation of the AuditService.
type KafkaProducer struct {
	writer *kafka.Writer
	logger logger.Logger
}

// NewKafkaProducer creates a new KafkaProducer.
func NewKafkaProducer(cfg config.KafkaConfig, logger logger.Logger) (service.AuditService, error) {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.AuditTopic,
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: cfg.WriteTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		RequiredAcks: kafka.RequiredAcks(cfg.RequiredAcks),
		BatchSize:    cfg.BatchSize,
		BatchTimeout: cfg.BatchTimeout,
	}
	return &KafkaProducer{
		writer: writer,
		logger: logger.WithComponent("KafkaProducer"),
	}, nil
}

// LogEvent sends an audit event to the Kafka topic.
func (p *KafkaProducer) LogEvent(ctx context.Context, event models.AuditEvent) error {
	bytes, err := json.Marshal(event)
	if err != nil {
		p.logger.Error(ctx, "failed to marshal audit event", err)
		return err
	}

	err = p.writer.WriteMessages(ctx, kafka.Message{
		Value: bytes,
	})
	if err != nil {
		p.logger.Error(ctx, "failed to write message to Kafka", err)
		// In a real implementation, you might add retry logic or a dead-letter queue.
	}
	return err
}

// Close closes the underlying Kafka writer.
func (p *KafkaProducer) Close() error {
	return p.writer.Close()
}
