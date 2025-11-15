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

// KafkaProducer provides a Kafka-backed implementation of the AuditService.
// It sends audit events as messages to a specified Kafka topic.
// KafkaProducer 提供了 AuditService 的 Kafka 支持实现。
// 它将审计事件作为消息发送到指定的 Kafka 主题。
type KafkaProducer struct {
	writer           *kafka.Writer
	revocationWriter *kafka.Writer
	logger           logger.Logger
}

// NewKafkaProducer creates and configures a new KafkaProducer.
// It initializes a kafka.Writer based on the provided configuration.
// NewKafkaProducer 创建并配置一个新的 KafkaProducer。
// 它根据提供的配置初始化一个 kafka.Writer。
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

	revocationWriter := &kafka.Writer{
		Addr:         kafka.TCP(cfg.Brokers...),
		Topic:        cfg.RevocationTopic,
		Balancer:     &kafka.LeastBytes{},
		WriteTimeout: cfg.WriteTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		RequiredAcks: kafka.RequiredAcks(cfg.RequiredAcks),
		BatchSize:    cfg.BatchSize,
		BatchTimeout: cfg.BatchTimeout,
	}

	return &KafkaProducer{
		writer:           writer,
		revocationWriter: revocationWriter,
		logger:           logger.WithComponent("KafkaProducer"),
	}, nil
}

// LogEvent marshals an AuditEvent to JSON and sends it as a message to the configured Kafka topic.
// LogEvent 将 AuditEvent 编组为 JSON，并将其作为消息发送到配置的 Kafka 主题。
func (p *KafkaProducer) LogEvent(ctx context.Context, event models.AuditEvent) error {
	bytes, err := json.Marshal(event)
	if err != nil {
		p.logger.Error(ctx, "failed to marshal audit event", err)
		return err
	}

	var targetWriter *kafka.Writer
	if event.Type == "token_revoked_globally" {
		targetWriter = p.revocationWriter
	} else {
		targetWriter = p.writer
	}

	err = targetWriter.WriteMessages(ctx, kafka.Message{
		Value: bytes,
	})
	if err != nil {
		p.logger.Error(ctx, "failed to write message to Kafka", err, "topic", targetWriter.Topic)
		// In a production implementation, add retry logic or a dead-letter queue here.
	}
	return err
}

// Close gracefully closes the underlying Kafka writer connection.
// Close 优雅地关闭底层的 Kafka writer 连接。
func (p *KafkaProducer) Close() error {
	if err := p.writer.Close(); err != nil {
		p.logger.Error(context.Background(), "failed to close audit writer", err)
	}
	if err := p.revocationWriter.Close(); err != nil {
		p.logger.Error(context.Background(), "failed to close revocation writer", err)
	}
	return nil // Or aggregate errors if needed
}
