// internal/application/service/tenant_app_service.go
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// TenantAppService defines the application service interface for tenant management use cases.
// TenantAppService 租户应用服务接口。
type TenantAppService interface {
	// GetTenantConfig retrieves the configuration for a specific tenant.
	// GetTenantConfig 获取租户配置。
	GetTenantConfig(ctx context.Context, tenantID string) (*dto.TenantConfigResponse, error)

	// UpdateTenantConfig updates the configuration for a specific tenant.
	// UpdateTenantConfig 更新租户配置。
	UpdateTenantConfig(ctx context.Context, tenantID string, req *dto.UpdateTenantConfigRequest) error

	// RotateTenantKey initiates a manual key rotation for a tenant.
	// RotateTenantKey 轮换租户密钥。
	RotateTenantKey(ctx context.Context, tenantID string, reason string) (*dto.KeyRotationResponse, error)

	// ListTenants retrieves a paginated list of all tenants.
	// ListTenants 列出所有租户。
	ListTenants(ctx context.Context, req *dto.ListTenantsRequest) (*dto.ListTenantsResponse, error)

	// CreateTenant creates a new tenant with default configurations and an initial key.
	// CreateTenant 创建租户。
	CreateTenant(ctx context.Context, req *dto.CreateTenantRequest) (*dto.TenantConfigResponse, error)

	// UpdateTenantStatus changes the lifecycle status of a tenant (e.g., active, suspended).
	// UpdateTenantStatus 更新租户状态。
	UpdateTenantStatus(ctx context.Context, tenantID string, status string) error

	// GetKeyRotationHistory retrieves the history of key rotations for a tenant.
	// GetKeyRotationHistory 获取密钥轮换历史。
	GetKeyRotationHistory(ctx context.Context, tenantID string) ([]*dto.KeyRotationHistory, error)
}

// tenantAppServiceImpl is the concrete implementation of the TenantAppService interface.
// tenantAppServiceImpl 租户应用服务实现。
type tenantAppServiceImpl struct {
	tenantRepo repository.TenantRepository
	kms        service.KeyManagementService
	cdnManager service.CDNCacheManager
	logger     logger.Logger
}

// NewTenantAppService creates a new instance of TenantAppService.
// NewTenantAppService 创建租户应用服务实例。
func NewTenantAppService(
	tenantRepo repository.TenantRepository,
	kms service.KeyManagementService,
	cdnManager service.CDNCacheManager,
	logger logger.Logger,
) TenantAppService {
	return &tenantAppServiceImpl{
		tenantRepo: tenantRepo,
		kms:        kms,
		cdnManager: cdnManager,
		logger:     logger,
	}
}

// GetTenantConfig retrieves the configuration for a specific tenant.
// GetTenantConfig 获取租户配置。
func (s *tenantAppServiceImpl) GetTenantConfig(ctx context.Context, tenantID string) (*dto.TenantConfigResponse, error) {
	s.logger.Info(ctx, "Getting tenant config", logger.String("tenant_id", tenantID))

	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, errors.New(errors.CodeNotFound, "tenant not found")
		}
		s.logger.Error(ctx, "Failed to get tenant config", err, logger.String("tenant_id", tenantID))
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get tenant config")
	}

	return s.convertTenantToDTO(tenant), nil
}

// UpdateTenantConfig updates a tenant's configuration.
// UpdateTenantConfig 更新租户配置。
func (s *tenantAppServiceImpl) UpdateTenantConfig(ctx context.Context, tenantID string, req *dto.UpdateTenantConfigRequest) error {
	s.logger.Info(ctx, "Updating tenant config", logger.String("tenant_id", tenantID))

	if err := s.validateUpdateTenantConfigRequest(req); err != nil {
		return err
	}

	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return errors.New(errors.CodeNotFound, "tenant not found")
		}
		return errors.Wrap(err, errors.CodeInternal, "failed to get tenant")
	}

	if req.AccessTokenTTL != nil {
		tenant.TokenTTLConfig.AccessTokenTTLSeconds = *req.AccessTokenTTL
	}
	if req.RefreshTokenTTL != nil {
		tenant.TokenTTLConfig.RefreshTokenTTLSeconds = *req.RefreshTokenTTL
	}
	tenant.UpdatedAt = time.Now()

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		s.logger.Error(ctx, "Failed to update tenant config", err, logger.String("tenant_id", tenantID))
		return errors.Wrap(err, errors.CodeInternal, "failed to update tenant config")
	}

	s.logger.Info(ctx, "Tenant config updated successfully", logger.String("tenant_id", tenantID))
	return nil
}

// RotateTenantKey handles the logic for manually rotating a tenant's signing key.
// RotateTenantKey 轮换租户密钥。
func (s *tenantAppServiceImpl) RotateTenantKey(ctx context.Context, tenantID string, reason string) (*dto.KeyRotationResponse, error) {
	s.logger.Info(ctx, "Starting tenant key rotation", logger.String("tenant_id", tenantID), logger.String("reason", reason))

	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, errors.New(errors.CodeNotFound, "tenant not found")
		}
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to get tenant")
	}

	if tenant.Status != constants.TenantStatusActive {
		return nil, errors.New(errors.CodeInvalidArgument, "tenant is not active")
	}

	oldKeyID := tenant.KeyRotationPolicy.ActiveKeyID

	newKeyID, err := s.kms.RotateTenantKey(ctx, tenantID, s.cdnManager)
	if err != nil {
		s.logger.Error(ctx, "Failed to rotate key using crypto service", err, logger.String("tenant_id", tenantID))
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to rotate key")
	}

	s.logger.Info(ctx, "Updating tenant config in database with new key", logger.String("tenant_id", tenantID), logger.String("new_key_id", newKeyID))
	tenant.KeyRotationPolicy.ActiveKeyID = newKeyID
	tenant.KeyRotationPolicy.LastRotatedAt = time.Now()
	tenant.UpdatedAt = time.Now()

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		s.logger.Error(ctx, "Failed to update tenant config after key rotation", err, logger.String("tenant_id", tenantID))
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to update tenant config")
	}

	s.logger.Info(ctx, "Key rotation completed successfully",
		logger.String("tenant_id", tenantID),
		logger.String("old_key_id", oldKeyID),
		logger.String("new_key_id", newKeyID),
		logger.String("reason", reason))

	return &dto.KeyRotationResponse{
		OldKeyID: oldKeyID,
		NewKeyID: newKeyID,
		Message:  "Key rotation successful",
	}, nil
}

// ListTenants retrieves a paginated list of all tenants.
// ListTenants 列出所有租户。
func (s *tenantAppServiceImpl) ListTenants(ctx context.Context, req *dto.ListTenantsRequest) (*dto.ListTenantsResponse, error) {
	s.logger.Info(ctx, "Listing tenants", logger.Int("page", req.Page), logger.Int("page_size", req.PageSize), logger.String("filter", req.Filter))

	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 || req.PageSize > 100 {
		req.PageSize = 20
	}

	tenants, total, err := s.tenantRepo.FindAll(ctx, req.PageSize, (req.Page-1)*req.PageSize)
	if err != nil {
		s.logger.Error(ctx, "Failed to list tenants", err)
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to list tenants")
	}

	tenantDTOs := make([]dto.TenantInfo, 0, len(tenants))
	for _, tenant := range tenants {
		tenantDTOs = append(tenantDTOs, dto.TenantInfo{
			TenantID:  tenant.TenantID,
			Name:      tenant.TenantName,
			Status:    string(tenant.Status),
			CreatedAt: tenant.CreatedAt.String(),
		})
	}

	return &dto.ListTenantsResponse{
		Tenants:    tenantDTOs,
		TotalCount: int(total),
	}, nil
}

// CreateTenant creates a new tenant, generates an initial signing key, and saves it to the database.
// CreateTenant 创建租户。
func (s *tenantAppServiceImpl) CreateTenant(ctx context.Context, req *dto.CreateTenantRequest) (*dto.TenantConfigResponse, error) {
	s.logger.Info(ctx, "Creating tenant", logger.String("tenant_name", req.Name))

	if err := s.validateCreateTenantRequest(req); err != nil {
		return nil, err
	}

	tenantID := fmt.Sprintf("tenant-%d", time.Now().Unix())

	newKeyID, err := s.kms.RotateTenantKey(ctx, tenantID, s.cdnManager)
	if err != nil {
		s.logger.Error(ctx, "Failed to generate initial key pair for new tenant", err, logger.String("tenant_id", tenantID))
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to generate initial key pair")
	}

	now := time.Now()
	tenant := &models.Tenant{
		TenantID:   tenantID,
		TenantName: req.Name,
		Status:     constants.TenantStatusActive,
		RateLimitConfig: models.RateLimitConfig{
			GlobalQPS:          100000,
			PerDeviceQPS:       50000,
			PerDevicePerMinute: 10,
			BurstSize:          200,
		},
		TokenTTLConfig: models.TokenTTLConfig{
			RefreshTokenTTLSeconds: 2592000, // 30 days
			AccessTokenTTLSeconds:  900,     // 15 minutes
		},
		KeyRotationPolicy: models.KeyRotationPolicy{
			ActiveKeyID:          newKeyID,
			RotationIntervalDays: 90,
			LastRotatedAt:        now,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.tenantRepo.Save(ctx, tenant); err != nil {
		s.logger.Error(ctx, "Failed to create tenant", err, logger.String("tenant_id", tenantID))
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to create tenant")
	}

	s.logger.Info(ctx, "Tenant created successfully", logger.String("tenant_id", tenantID), logger.String("tenant_name", req.Name))
	return s.convertTenantToDTO(tenant), nil
}

// UpdateTenantStatus updates the lifecycle status of a tenant.
// UpdateTenantStatus 更新租户状态。
func (s *tenantAppServiceImpl) UpdateTenantStatus(ctx context.Context, tenantID string, status string) error {
	s.logger.Info(ctx, "Updating tenant status", logger.String("tenant_id", tenantID), logger.String("new_status", status))

	validStatuses := map[string]bool{
		string(constants.TenantStatusActive):    true,
		string(constants.TenantStatusSuspended): true,
		string(constants.TenantStatusDeleted):   true,
	}
	if !validStatuses[status] {
		return errors.New(errors.CodeInvalidArgument, fmt.Sprintf("invalid status: %s", status))
	}

	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return errors.New(errors.CodeNotFound, "tenant not found")
		}
		return errors.Wrap(err, errors.CodeInternal, "failed to get tenant")
	}

	tenant.Status = constants.TenantStatus(status)
	tenant.UpdatedAt = time.Now()

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		s.logger.Error(ctx, "Failed to update tenant status", err, logger.String("tenant_id", tenantID))
		return errors.Wrap(err, errors.CodeInternal, "failed to update tenant status")
	}

	s.logger.Info(ctx, "Tenant status updated successfully", logger.String("tenant_id", tenantID), logger.String("new_status", status))
	return nil
}

// GetKeyRotationHistory retrieves the history of key rotations for a tenant. (Stub implementation)
// GetKeyRotationHistory 获取密钥轮换历史。
func (s *tenantAppServiceImpl) GetKeyRotationHistory(ctx context.Context, tenantID string) ([]*dto.KeyRotationHistory, error) {
	s.logger.Info(ctx, "Getting key rotation history", logger.String("tenant_id", tenantID))

	// This is a stub implementation. A real implementation would fetch history from the KMS or a dedicated log.
	history := make([]*dto.KeyRotationHistory, 0)
	s.logger.Warn(ctx, "GetKeyRotationHistory is not fully implemented due to missing domain service method")

	return history, nil
}

// convertTenantToDTO 转换租户模型为 DTO
func (s *tenantAppServiceImpl) convertTenantToDTO(tenant *models.Tenant) *dto.TenantConfigResponse {
	return &dto.TenantConfigResponse{
		TenantID:        tenant.TenantID,
		AccessTokenTTL:  tenant.TokenTTLConfig.AccessTokenTTLSeconds,
		RefreshTokenTTL: tenant.TokenTTLConfig.RefreshTokenTTLSeconds,
	}
}


// validateUpdateTenantConfigRequest 验证更新租户配置请求
func (s *tenantAppServiceImpl) validateUpdateTenantConfigRequest(req *dto.UpdateTenantConfigRequest) error {
	if req.AccessTokenTTL != nil && *req.AccessTokenTTL <= 0 {
		return errors.New(errors.CodeInvalidArgument, "access_token_ttl must be positive")
	}
	if req.RefreshTokenTTL != nil && *req.RefreshTokenTTL <= 0 {
		return errors.New(errors.CodeInvalidArgument, "refresh_token_ttl must be positive")
	}
	if req.AccessTokenTTL != nil && req.RefreshTokenTTL != nil && *req.RefreshTokenTTL <= *req.AccessTokenTTL {
		return errors.New(errors.CodeInvalidArgument, "refresh_token_ttl must be greater than access_token_ttl")
	}
	return nil
}

// validateCreateTenantRequest 验证创建租户请求
func (s *tenantAppServiceImpl) validateCreateTenantRequest(req *dto.CreateTenantRequest) error {
	if req.Name == "" {
		return errors.New(errors.CodeInvalidArgument, "tenant_name is required")
	}
	if len(req.Name) < 3 || len(req.Name) > 256 {
		return errors.New(errors.CodeInvalidArgument, "tenant_name must be between 3 and 256 characters")
	}
	return nil
}

//Personal.AI order the ending

