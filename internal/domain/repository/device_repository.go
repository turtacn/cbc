package repository

import (
	"context"
	"github.com/turtacn/cbc/internal/domain/models"
)

// DeviceRepository defines the interface for device persistence.
type DeviceRepository interface {
	FindByID(ctx context.Context, agentID string) (*models.Device, error)
	Save(ctx context.Context, device *models.Device) error
	Update(ctx context.Context, device *models.Device) error
	FindByTenantID(ctx context.Context, tenantID string, page, pageSize int) ([]*models.Device, int64, error)
}
