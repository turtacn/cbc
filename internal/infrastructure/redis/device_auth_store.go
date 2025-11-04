// Package redis provides Redis-backed implementations of domain interfaces.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
)

const (
	deviceCodeKeyPrefix = "dev_auth:dc:"
	userCodeKeyPrefix   = "dev_auth:uc:"
)

// redisDeviceAuthStore is a Redis-backed implementation of the DeviceAuthStore interface.
type redisDeviceAuthStore struct {
	client *redis.Client
}

// NewRedisDeviceAuthStore creates a new instance of redisDeviceAuthStore.
func NewRedisDeviceAuthStore(client *redis.Client) service.DeviceAuthStore {
	return &redisDeviceAuthStore{client: client}
}

// CreateSession stores a new device authorization session in Redis.
func (s *redisDeviceAuthStore) CreateSession(ctx context.Context, session *models.DeviceAuthSession) error {
	pipe := s.client.TxPipeline()

	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	dcKey := deviceCodeKeyPrefix + session.DeviceCode
	ucKey := userCodeKeyPrefix + session.UserCode
	ttl := time.Until(session.ExpiresAt)

	pipe.Set(ctx, dcKey, sessionData, ttl)
	pipe.Set(ctx, ucKey, session.DeviceCode, ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to execute redis transaction for session creation: %w", err)
	}
	return nil
}

// GetSessionByDeviceCode retrieves a session by its device code.
func (s *redisDeviceAuthStore) GetSessionByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceAuthSession, error) {
	key := deviceCodeKeyPrefix + deviceCode
	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // Not found is not an error
		}
		return nil, fmt.Errorf("failed to get session by device code from redis: %w", err)
	}

	var session models.DeviceAuthSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}
	return &session, nil
}

// GetSessionByUserCode retrieves a session by its user code.
func (s *redisDeviceAuthStore) GetSessionByUserCode(ctx context.Context, userCode string) (*models.DeviceAuthSession, error) {
	ucKey := userCodeKeyPrefix + userCode
	deviceCode, err := s.client.Get(ctx, ucKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get device code by user code: %w", err)
	}

	return s.GetSessionByDeviceCode(ctx, deviceCode)
}

// ApproveSession marks a session as approved.
func (s *redisDeviceAuthStore) ApproveSession(ctx context.Context, userCode, tenantID, subject string) error {
	deviceCode, err := s.client.Get(ctx, userCodeKeyPrefix+userCode).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return errors.New("session not found")
		}
		return fmt.Errorf("failed to get device code by user code: %w", err)
	}

	dcKey := deviceCodeKeyPrefix + deviceCode
	return s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, dcKey).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return errors.New("session not found")
			}
			return err
		}

		var session models.DeviceAuthSession
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			return fmt.Errorf("failed to unmarshal session data: %w", err)
		}

		session.Status = models.DeviceAuthStatusApproved
		session.TenantID = tenantID
		session.Subject = subject

		newData, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session data: %w", err)
		}

		pipe := tx.TxPipeline()
		pipe.Set(ctx, dcKey, newData, time.Until(session.ExpiresAt))
		_, err = pipe.Exec(ctx)
		return err
	})
}

// DenySession marks a session as denied.
func (s *redisDeviceAuthStore) DenySession(ctx context.Context, userCode string) error {
	deviceCode, err := s.client.Get(ctx, userCodeKeyPrefix+userCode).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return errors.New("session not found")
		}
		return fmt.Errorf("failed to get device code by user code: %w", err)
	}

	dcKey := deviceCodeKeyPrefix + deviceCode
	return s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, dcKey).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return errors.New("session not found")
			}
			return err
		}

		var session models.DeviceAuthSession
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			return fmt.Errorf("failed to unmarshal session data: %w", err)
		}

		session.Status = models.DeviceAuthStatusDenied

		newData, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session data: %w", err)
		}

		pipe := tx.TxPipeline()
		pipe.Set(ctx, dcKey, newData, time.Until(session.ExpiresAt))
		_, err = pipe.Exec(ctx)
		return err
	})
}

// TouchPoll updates the last poll timestamp for a session.
func (s *redisDeviceAuthStore) TouchPoll(ctx context.Context, deviceCode string) error {
	dcKey := deviceCodeKeyPrefix + deviceCode
	return s.client.Watch(ctx, func(tx *redis.Tx) error {
		data, err := tx.Get(ctx, dcKey).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return errors.New("session not found")
			}
			return err
		}

		var session models.DeviceAuthSession
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			return fmt.Errorf("failed to unmarshal session data: %w", err)
		}

		session.LastPollAt = time.Now()

		newData, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session data: %w", err)
		}

		pipe := tx.TxPipeline()
		pipe.Set(ctx, dcKey, newData, time.Until(session.ExpiresAt))
		_, err = pipe.Exec(ctx)
		return err
	})
}
