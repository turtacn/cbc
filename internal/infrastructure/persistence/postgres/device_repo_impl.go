package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type deviceRepositoryImpl struct {
	db  *DBConnection
	log logger.Logger
}

// NewDeviceRepository creates a new PostgreSQL-backed DeviceRepository.
func NewDeviceRepository(db *DBConnection, log logger.Logger) repository.DeviceRepository {
	return &deviceRepositoryImpl{db: db, log: log}
}

// Save persists a new device or updates an existing one.
func (r *deviceRepositoryImpl) Save(ctx context.Context, device *models.Device) *errors.AppError {
	query := `
		INSERT INTO devices (id, device_id, tenant_id, device_type, os, app_version, fingerprint, registered_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, device_id) DO UPDATE SET
			device_type = EXCLUDED.device_type,
			os = EXCLUDED.os,
			app_version = EXCLUDED.app_version,
			fingerprint = EXCLUDED.fingerprint,
			last_seen_at = EXCLUDED.last_seen_at
	`
	_, err := r.db.Pool.Exec(ctx, query,
		device.ID, device.DeviceID, device.TenantID, device.DeviceType, device.OS,
		device.AppVersion, device.Fingerprint, device.RegisteredAt, device.LastSeenAt,
	)

	if err != nil {
		r.log.Error(ctx, "Failed to save device", err)
		return errors.ErrDatabase.WithError(err)
	}
	return nil
}

// FindByID retrieves a device by its internal UUID.
func (r *deviceRepositoryImpl) FindByID(ctx context.Context, id uuid.UUID) (*models.Device, *errors.AppError) {
	query := `SELECT id, device_id, tenant_id, device_type, os, app_version, fingerprint, status, registered_at, last_seen_at FROM devices WHERE id = $1`
	row := r.db.Pool.QueryRow(ctx, query, id)
	return r.scanDevice(ctx, row)
}

// FindByDeviceID retrieves a device by its agent-provided unique ID within a tenant.
func (r *deviceRepositoryImpl) FindByDeviceID(ctx context.Context, tenantID uuid.UUID, deviceID string) (*models.Device, *errors.AppError) {
	query := `SELECT id, device_id, tenant_id, device_type, os, app_version, fingerprint, status, registered_at, last_seen_at FROM devices WHERE tenant_id = $1 AND device_id = $2`
	row := r.db.Pool.QueryRow(ctx, query, tenantID, deviceID)
	return r.scanDevice(ctx, row)
}

// FindByTenantID retrieves all devices for a specific tenant.
func (r *deviceRepositoryImpl) FindByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Device, *errors.AppError) {
	query := `SELECT id, device_id, tenant_id, device_type, os, app_version, fingerprint, status, registered_at, last_seen_at FROM devices WHERE tenant_id = $1 ORDER BY registered_at DESC LIMIT $2 OFFSET $3`
	rows, err := r.db.Pool.Query(ctx, query, tenantID, limit, offset)
	if err != nil {
		r.log.Error(ctx, "Failed to query devices by tenant", err)
		return nil, errors.ErrDatabase.WithError(err)
	}
	defer rows.Close()

	devices := make([]*models.Device, 0)
	for rows.Next() {
		device, appErr := r.scanDevice(ctx, rows)
		if appErr != nil {
			return nil, appErr
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// UpdateLastSeen updates the last_seen_at timestamp for a device.
func (r *deviceRepositoryImpl) UpdateLastSeen(ctx context.Context, id uuid.UUID, lastSeenAt time.Time) *errors.AppError {
	query := `UPDATE devices SET last_seen_at = $1 WHERE id = $2`
	_, err := r.db.Pool.Exec(ctx, query, lastSeenAt, id)
	if err != nil {
		r.log.Error(ctx, "Failed to update last seen for device", err)
		return errors.ErrDatabase.WithError(err)
	}
	return nil
}

func (r *deviceRepositoryImpl) scanDevice(ctx context.Context, row pgx.Row) (*models.Device, *errors.AppError) {
	var device models.Device
	err := row.Scan(
		&device.ID, &device.DeviceID, &device.TenantID, &device.DeviceType,
		&device.OS, &device.AppVersion, &device.Fingerprint, &device.Status,
		&device.RegisteredAt, &device.LastSeenAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.ErrNotFound
		}
		r.log.Error(ctx, "Failed to scan device row", err)
		return nil, errors.ErrDatabase.WithError(err)
	}
	return &device, nil
}

//Personal.AI order the ending
