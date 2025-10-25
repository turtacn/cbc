package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// TenantAppService defines the interface for tenant-related application services.
type TenantAppService interface {
	GetTenantConfig(ctx context.Context, tenantID uuid.UUID) (*models.Tenant, *errors.AppError)
	UpdateTenantConfig(ctx context.Context, tenant *models.Tenant) (*models.Tenant, *errors.AppError)
	RotateTenantKey(ctx context.Context, tenantID uuid.UUID) *errors.AppError
}

type tenantAppServiceImpl struct {
	tenantRepo repository.TenantRepository
	cryptoSvc  service.CryptoService
	log        logger.Logger
}

// NewTenantAppService creates a new TenantAppService.
func NewTenantAppService(
	tenantRepo repository.TenantRepository,
	cryptoSvc service.CryptoService,
	log logger.Logger,
) TenantAppService {
	return &tenantAppServiceImpl{
		tenantRepo: tenantRepo,
		cryptoSvc:  cryptoSvc,
		log:        log,
	}
}

// GetTenantConfig retrieves a tenant's configuration.
func (s *tenantAppServiceImpl) GetTenantConfig(ctx context.Context, tenantID uuid.UUID) (*models.Tenant, *errors.AppError) {
	return s.tenantRepo.FindByID(ctx, tenantID)
}

// UpdateTenantConfig updates a tenant's configuration.
func (s *tenantAppServiceImpl) UpdateTenantConfig(ctx context.Context, tenant *models.Tenant) (*models.Tenant, *errors.AppError) {
	if err := s.tenantRepo.UpdateConfig(ctx, tenant); err != nil {
		return nil, err
	}
	s.log.Info(ctx, "Tenant config updated", logger.Fields{"tenant_id": tenant.ID})
	return tenant, nil
}

// RotateTenantKey handles the logic for rotating a tenant's signing key.
func (s *tenantAppServiceImpl) RotateTenantKey(ctx context.Context, tenantID uuid.UUID) *errors.AppError {
	s.log.Info(ctx, "Starting key rotation for tenant", logger.Fields{"tenant_id": tenantID})
	// 1. Generate new key pair via CryptoService (which interacts with Vault)
	// 2. Update tenant config with new key ID
	// 3. Mark old key as deprecated in Vault
	// 4. Invalidate caches
	// This is a complex process that would be fully implemented in a real system.
	// For now, this is a placeholder for the logic.
	return nil
}

//Personal.AI order the ending
