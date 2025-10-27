// Package postgres implements PostgreSQL-based device repository for trusted device management.
// It provides device fingerprint verification, trust scoring, and device lifecycle management.
package postgres

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// DeviceRepoImpl implements DeviceRepository interface using PostgreSQL.
// It manages device registration, trust scoring, and fingerprint validation.
type DeviceRepoImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewDeviceRepository creates a new PostgreSQL-based device repository instance.
func NewDeviceRepository(db *gorm.DB, log logger.Logger) repository.DeviceRepository {
	return &DeviceRepoImpl{
		db:     db,
		logger: log,
	}
}

// Save registers a new device in the system.
func (r *DeviceRepoImpl) Save(ctx context.Context, device *models.Device) error {
	startTime := time.Now()

	// Set creation timestamp
	now := time.Now()
	device.RegisteredAt = now
	device.LastSeenAt = now
	device.CreatedAt = now
	device.UpdatedAt = now

	// Create device record
	if err := r.db.WithContext(ctx).Create(device).Error; err != nil {
		r.logger.Error(ctx, "Failed to create device", err,
			logger.String("agent_id", device.DeviceID),
			logger.String("fingerprint", device.DeviceFingerprint),
		)
		return errors.New(errors.CodeInternal, "failed to create device")
	}

	latency := time.Since(startTime)
	r.logger.Info(ctx, "Device created successfully",
		logger.String("device_id", device.DeviceID),
		logger.String("fingerprint", device.DeviceFingerprint),
		logger.String("trust_level", string(device.TrustLevel)),
		logger.Int64("latency_ms", latency.Milliseconds()),
	)

	return nil
}

// Update modifies an existing device record.
func (r *DeviceRepoImpl) Update(ctx context.Context, device *models.Device) error {
	device.UpdatedAt = time.Now()

	result := r.db.WithContext(ctx).
		Model(device).
		Where("device_id = ?", device.DeviceID).
		Updates(device)

	if result.Error != nil {
		r.logger.Error(ctx, "Failed to update device", result.Error,
			logger.String("device_id", device.DeviceID),
		)
		return errors.New(errors.CodeInternal, "failed to update device")
	}

	if result.RowsAffected == 0 {
		r.logger.Warn(ctx, "Device not found for update", logger.String("device_id", device.DeviceID))
		return errors.New(errors.CodeNotFound, "device not found for update")
	}

	r.logger.Info(ctx, "Device updated successfully",
		logger.String("device_id", device.DeviceID),
	)

	return nil
}

// FindByID retrieves a device by its unique identifier.
func (r *DeviceRepoImpl) FindByID(ctx context.Context, agentID string) (*models.Device, error) {
	var device models.Device

	err := r.db.WithContext(ctx).
		Where("device_id = ?", agentID).
		First(&device).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			r.logger.Debug(ctx, "Device not found", logger.String("device_id", agentID))
			return nil, errors.New(errors.CodeNotFound, "device not found")
		}
		r.logger.Error(ctx, "Failed to retrieve device by ID", err,
			logger.String("device_id", agentID),
		)
		return nil, errors.New(errors.CodeInternal, "failed to retrieve device by ID")
	}

	return &device, nil
}


func (r *DeviceRepoImpl) FindByTenantID(ctx context.Context, tenantID string, limit, offset int) ([]*models.Device, int64, error) {
	return nil, 0, fmt.Errorf("not implemented")
}


func (r *DeviceRepoImpl) FindByFingerprint(ctx context.Context, tenantID, fingerprint string) (*models.Device, error) {
	var device models.Device
	err := r.db.WithContext(ctx).Where("tenant_id = ? AND device_fingerprint = ?", tenantID, fingerprint).First(&device).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.ErrDeviceNotFound(fingerprint)
		}
		return nil, err
	}
	return &device, nil
}


func (r *DeviceRepoImpl) Exists(ctx context.Context, agentID string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Device{}).Where("device_id = ?", agentID).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// BatchUpdateLastSeen updates the last seen timestamp for multiple devices.
func (r *DeviceRepoImpl) BatchUpdateLastSeen(ctx context.Context, updates map[string]time.Time) error {
	if len(updates) == 0 {
		return nil
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for deviceID, lastSeenAt := range updates {
			result := tx.Model(&models.Device{}).
				Where("device_id = ?", deviceID).
				Updates(map[string]interface{}{
					"last_seen_at": lastSeenAt,
					"updated_at":   time.Now(),
				})
			if result.Error != nil {
				return result.Error
			}
		}
		return nil
	})
}


func (r *DeviceRepoImpl) UpdateLastSeen(ctx context.Context, agentID string, lastSeenAt time.Time) error {
    result := r.db.WithContext(ctx).
        Model(&models.Device{}).
        Where("device_id = ?", agentID).
        Updates(map[string]interface{}{
            "last_seen_at":  lastSeenAt,
            "updated_at":    time.Now(),
        })

    if result.Error != nil {
        r.logger.Error(ctx, "Failed to update device last seen", result.Error,
            logger.String("device_id", agentID),
        )
        return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
    }

    if result.RowsAffected == 0 {
        r.logger.Debug(ctx, "Device not found for last seen update", logger.String("device_id", agentID))
        return errors.ErrDeviceNotFound(agentID)
    }

    r.logger.Debug(ctx, "Device last seen updated", logger.String("device_id", agentID))
    return nil
}


func (r *DeviceRepoImpl) UpdateTrustLevel(ctx context.Context, agentID string, trustLevel constants.TrustLevel) error {
	return fmt.Errorf("not implemented")
}

func (r *DeviceRepoImpl) UpdateStatus(ctx context.Context, agentID string, status constants.DeviceStatus) error {
	return fmt.Errorf("not implemented")
}

// Delete removes a device record from the system.
func (r *DeviceRepoImpl) Delete(ctx context.Context, agentID string) error {
	result := r.db.WithContext(ctx).
		Where("device_id = ?", agentID).
		Delete(&models.Device{})

	if result.Error != nil {
		r.logger.Error(ctx, "Failed to delete device", result.Error,
			logger.String("device_id", agentID),
		)
		return fmt.Errorf("%w: %v", errors.ErrDatabaseOperation, result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug(ctx, "Device not found for deletion", logger.String("device_id", agentID))
		return errors.ErrDeviceNotFound(agentID)
	}

	r.logger.Info(ctx, "Device deleted successfully", logger.String("device_id", agentID))
	return nil
}

func (r *DeviceRepoImpl) CountByTenantID(ctx context.Context, tenantID string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Device{}).Where("tenant_id = ?", tenantID).Count(&count).Error
	return count, err
}

func (r *DeviceRepoImpl) CountActiveByTenantID(ctx context.Context, tenantID string) (int64, error) {
	return 0, fmt.Errorf("not implemented")
}

func (r *DeviceRepoImpl) FindInactiveDevices(ctx context.Context, inactiveSince time.Time, limit, offset int) ([]*models.Device, int64, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (r *DeviceRepoImpl) FindByTrustLevel(ctx context.Context, tenantID string, trustLevel constants.TrustLevel, limit, offset int) ([]*models.Device, int64, error) {
	return nil, 0, fmt.Errorf("not implemented")
}

func (r *DeviceRepoImpl) GetDeviceMetrics(ctx context.Context, tenantID string) (*repository.DeviceMetrics, error) {
	return nil, fmt.Errorf("not implemented")
}
