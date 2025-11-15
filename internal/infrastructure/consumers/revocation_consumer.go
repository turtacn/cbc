// Package consumers contains Kafka consumers for various background processing tasks.
package consumers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/segmentio/kafka-go"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/logger"
)

// RevocationConsumer listens for global token revocation events from other regions
// and writes them to the local Redis blacklist. This is the "fan-in" part of the
// global revocation mechanism.
type RevocationConsumer struct {
	reader *kafka.Reader
	rdb    redis.UniversalClient
	logger logger.Logger
	stop   chan struct{}
}

// NewRevocationConsumer creates a new consumer for global revocation events.
func NewRevocationConsumer(cfg config.KafkaConfig, rdb redis.UniversalClient, log logger.Logger) *RevocationConsumer {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        cfg.Brokers,
		Topic:          cfg.RevocationTopic,
		GroupID:        "cbc-revocation-consumers", // All instances of the service share the same group ID
		MinBytes:       10e3,                       // 10KB
		MaxBytes:       10e6,                       // 10MB
		CommitInterval: time.Second,
	})

	return &RevocationConsumer{
		reader: reader,
		rdb:    rdb,
		logger: log.WithComponent("RevocationConsumer"),
		stop:   make(chan struct{}),
	}
}

// Start begins the consumer loop. It's a blocking call and should be run in a goroutine.
func (c *RevocationConsumer) Start(ctx context.Context) {
	c.logger.Info(ctx, "starting global revocation consumer...")
	for {
		select {
		case <-c.stop:
			c.logger.Info(ctx, "stopping global revocation consumer...")
			return
		default:
			msg, err := c.reader.FetchMessage(ctx)
			if err != nil {
				c.logger.Error(ctx, "failed to fetch message from kafka", err)
				continue
			}

			var event models.AuditEvent
			if err := json.Unmarshal(msg.Value, &event); err != nil {
				c.logger.Error(ctx, "failed to unmarshal revocation event", err, logger.String("kafka_message", string(msg.Value)))
				// Acknowledge the message to avoid reprocessing a poison pill.
				c.reader.CommitMessages(ctx, msg)
				continue
			}

			if err := c.handleEvent(ctx, event); err != nil {
				c.logger.Error(ctx, "failed to handle revocation event", err, logger.String("jti", event.Metadata["jti"]))
				// Do not commit the message, allow for reprocessing.
			} else {
				c.reader.CommitMessages(ctx, msg)
			}
		}
	}
}

// Stop gracefully shuts down the consumer.
func (c *RevocationConsumer) Stop() {
	close(c.stop)
	if err := c.reader.Close(); err != nil {
		c.logger.Error(context.Background(), "failed to close kafka reader", err)
	}
}

func (c *RevocationConsumer) handleEvent(ctx context.Context, event models.AuditEvent) error {
	jti, ok := event.Metadata["jti"]
	if !ok || jti == "" {
		return &consumerError{message: "event metadata missing 'jti' field"}
	}

	expiresAtStr, ok := event.Metadata["expires_at"]
	if !ok || expiresAtStr == "" {
		return &consumerError{message: "event metadata missing 'expires_at' field"}
	}

	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return &consumerError{message: "failed to parse 'expires_at' field", underlying: err}
	}

	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		c.logger.Warn(ctx, "received expired revocation event, skipping", logger.String("jti", jti))
		return nil
	}

	// The key format must match the one used by the TokenBlacklistStore.
	key := "cbc:bl:" + event.TenantID + ":" + jti
	c.logger.Debug(ctx, "applying global revocation to local redis", logger.String("key", key), logger.Duration("ttl", ttl))
	return c.rdb.Set(ctx, key, "1", ttl).Err()
}

// consumerError is a custom error type for consumer-specific failures.
type consumerError struct {
	message    string
	underlying error
}

func (e *consumerError) Error() string {
	if e.underlying != nil {
		return e.message + ": " + e.underlying.Error()
	}
	return e.message
}
