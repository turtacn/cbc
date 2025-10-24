package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
)

// DeviceRepository defines the interface for interacting with device storage.
type DeviceRepository interface {
	// Save persists a new device or updates an existing one.
	Save(ctx context.Context, device *models.Device) *errors.AppError

	// FindByID retrieves a device by its internal UUID.
	FindByID(ctx context.Context, id uuid.UUID) (*models.Device, *errors.AppError)

	// FindByDeviceID retrieves a device by its agent-provided unique ID within a tenant.
	FindByDeviceID(ctx context.Context, tenantID uuid.UUID, deviceID string) (*models.Device, *errors.AppError)

	// FindByTenantID retrieves all devices for a specific tenant, with pagination.
	FindByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.Device, *errors.AppError)

	// UpdateLastSeen updates the last_seen_at timestamp for a specific device.
	UpdateLastSeen(ctx context.Context, id uuid.UUID, lastSeenAt time.Time) *errors.AppError
}
//Personal.AI order the ending