package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/errors"
)

// TenantRepository defines the interface for interacting with tenant storage.
type TenantRepository interface {
	// FindByID retrieves a tenant by its UUID, including its configuration.
	FindByID(ctx context.Context, id uuid.UUID) (*models.Tenant, *errors.AppError)

	// FindAll retrieves a list of all tenants, with pagination.
	FindAll(ctx context.Context, limit, offset int) ([]*models.Tenant, *errors.AppError)

	// UpdateConfig updates a tenant's configuration.
	UpdateConfig(ctx context.Context, tenant *models.Tenant) *errors.AppError

	// Save persists a new tenant.
	Save(ctx context.Context, tenant *models.Tenant) *errors.AppError
}
//Personal.AI order the ending