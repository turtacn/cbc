// Package postgres implements PostgreSQL-based device repository for trusted device management.
// It provides device fingerprint verification, trust scoring, and device lifecycle management.
package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
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
func (r *DeviceRepoImpl) Save(ctx context.Context, d *models.Device) error {
	startTime := time.Now()

	// Set creation timestamp
	now := time.Now()
	d.RegisteredAt = now
	d.LastSeenAt = now
	d.CreatedAt = now
	d.UpdatedAt = now

	// Create device record
	if err := r.db.WithContext(ctx).Create(d).Error; err != nil {
		r.logger.Error(ctx, "Failed to create device", err,
			logger.String("agent_id", d.DeviceID),
		)
		return mapPgErr(err)
	}

	latency := time.Since(startTime)
	r.logger.Info(ctx, "Device created successfully",
		logger.String("device_id", d.DeviceID),
		logger.Int64("latency_ms", latency.Milliseconds()),
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
			return nil, errors.ErrDeviceNotFound(agentID)
		}
		r.logger.Error(ctx, "Failed to retrieve device by ID", err,
			logger.String("device_id", agentID),
		)
		return nil, errors.ErrServerError("failed to retrieve device by ID")
	}

	return &device, nil
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
		return errors.ErrServerError("failed to update device")
	}

	if result.RowsAffected == 0 {
		r.logger.Warn(ctx, "Device not found for update", logger.String("device_id", device.DeviceID))
		return errors.ErrDeviceNotFound(device.DeviceID)
	}

	r.logger.Info(ctx, "Device updated successfully",
		logger.String("device_id", device.DeviceID),
	)

	return nil
}

// FindByTenantID retrieves a list of devices for a given tenant.
func (r *DeviceRepoImpl) FindByTenantID(ctx context.Context, tenantID string, page, pageSize int) ([]*models.Device, int64, error) {
	var devices []*models.Device
	var total int64

	offset := (page - 1) * pageSize

	err := r.db.WithContext(ctx).
		Model(&models.Device{}).
		Where("tenant_id = ?", tenantID).
		Count(&total).
		Limit(pageSize).
		Offset(offset).
		Find(&devices).Error

	if err != nil {
		r.logger.Error(ctx, "Failed to list devices by tenant", err, logger.String("tenant_id", tenantID))
		return nil, 0, errors.ErrServerError("failed to list devices by tenant")
	}

	return devices, total, nil
}


func mapPgErr(err error) error {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		if pgErr.Code == "23505" { // unique_violation
			return errors.ErrInvalidRequest("device already exists")
		}
	}
	return err
}
