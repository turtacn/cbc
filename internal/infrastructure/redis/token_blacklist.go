package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

type tokenBlacklist struct {
	rdb      redis.UniversalClient
	producer service.AuditService
	logger   logger.Logger
}

func NewTokenBlacklistStore(rdb redis.UniversalClient, producer service.AuditService, log logger.Logger) service.TokenBlacklistStore {
	return &tokenBlacklist{
		rdb:      rdb,
		producer: producer,
		logger:   log.WithComponent("TokenBlacklist"),
	}
}

func key(tenantID, jti string) string { return fmt.Sprintf("cbc:bl:%s:%s", tenantID, jti) }

func (b *tokenBlacklist) Revoke(ctx context.Context, tenantID, jti string, exp time.Time) error {
	ttl := time.Until(exp)
	if ttl <= 0 {
		return nil
	}

	// First, perform the local revocation in Redis.
	if err := b.rdb.Set(ctx, key(tenantID, jti), "1", ttl).Err(); err != nil {
		return err
	}

	// Then, publish the global revocation event.
	event := models.AuditEvent{
		Action:   "token_revoked_globally",
		TenantID: tenantID,
		Actor:    "system",
		Metadata: models.Metadata{
			"jti":        jti,
			"expires_at": exp.Format(time.RFC3339),
		},
	}

	if err := b.producer.LogEvent(ctx, event); err != nil {
		// If publishing fails, we must log a critical error as it leads to inconsistency.
		b.logger.Error(ctx, "CRITICAL: failed to publish global token revocation event", err, logger.String("jti", jti), logger.String("tenant_id", tenantID))
		// We do not return the error to the client, as the local revocation succeeded.
		// The system is now in an inconsistent state that requires monitoring and alerting.
	}

	return nil
}

func (b *tokenBlacklist) IsRevoked(ctx context.Context, tenantID, jti string) (bool, error) {
	n, err := b.rdb.Exists(ctx, key(tenantID, jti)).Result()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}
