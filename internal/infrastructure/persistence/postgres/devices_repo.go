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

// DeviceRepoImpl provides the PostgreSQL implementation of the DeviceRepository interface.
// It handles the persistence and retrieval of device information.
// DeviceRepoImpl 提供了 DeviceRepository 接口的 PostgreSQL 实现。
// 它处理设备信息的持久化和检索。
type DeviceRepoImpl struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewDeviceRepository creates a new instance of the PostgreSQL-based device repository.
// NewDeviceRepository 创建一个新的基于 PostgreSQL 的设备仓库实例。
func NewDeviceRepository(db *gorm.DB, log logger.Logger) repository.DeviceRepository {
	return &DeviceRepoImpl{
		db:     db,
		logger: log,
	}
}

// Save persists a new device record to the database.
// It sets the initial timestamps and handles potential unique constraint violations.
// Save 将新的设备记录持久化到数据库。
// 它设置初始时间戳并处理潜在的唯一约束冲突。
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

// FindByID retrieves a single device from the database by its unique device ID.
// It returns a `DeviceNotFound` error if no matching record is found.
// FindByID 通过其唯一的设备 ID 从数据库中检索单个设备。
// 如果找不到匹配的记录，它将返回 `DeviceNotFound` 错误。
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

// Update modifies the details of an existing device in the database.
// It automatically updates the `UpdatedAt` timestamp.
// It returns a `DeviceNotFound` error if the device to be updated does not exist.
// Update 修改数据库中现有设备的详细信息。
// 它会自动更新 `UpdatedAt` 时间戳。
// 如果要更新的设备不存在，它将返回 `DeviceNotFound` 错误。
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

// FindByTenantID retrieves a paginated list of devices associated with a specific tenant ID.
// It also returns the total count of devices for that tenant to aid in pagination.
// FindByTenantID 检索与特定租户 ID 关联的设备的分页列表。
// 它还返回该租户的设备总数以帮助分页。
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

// mapPgErr is a helper function to translate specific PostgreSQL errors into domain-specific errors.
// For example, it maps a unique violation error (code 23505) to a more meaningful "device already exists" error.
// mapPgErr 是一个辅助函数，用于将特定的 PostgreSQL 错误转换为领域特定的错误。
// 例如，它将唯一性冲突错误（代码 23505）映射为更有意义的“设备已存在”错误。
func mapPgErr(err error) error {
	if pgErr, ok := err.(*pgconn.PgError); ok {
		if pgErr.Code == "23505" { // unique_violation
			return errors.ErrInvalidRequest("device already exists")
		}
	}
	return err
}
