// internal/application/service/tenant_app_service.go
package service

import (
	"context"
	"fmt"
	"time"

	"cbc/internal/application/dto"
	"cbc/internal/domain/models"
	"cbc/internal/domain/repository"
	"cbc/internal/domain/service"
	"cbc/pkg/errors"
	"cbc/pkg/logger"
)

// TenantAppService 租户应用服务接口
type TenantAppService interface {
	// GetTenantConfig 获取租户配置
	GetTenantConfig(ctx context.Context, tenantID string) (*dto.TenantConfigResponse, error)

	// UpdateTenantConfig 更新租户配置
	UpdateTenantConfig(ctx context.Context, req *dto.UpdateTenantConfigRequest) error

	// RotateTenantKey 轮换租户密钥
	RotateTenantKey(ctx context.Context, tenantID string, reason string) (*dto.KeyRotationResponse, error)

	// ListTenants 列出所有租户
	ListTenants(ctx context.Context, req *dto.ListTenantsRequest) (*dto.ListTenantsResponse, error)

	// CreateTenant 创建租户
	CreateTenant(ctx context.Context, req *dto.CreateTenantRequest) (*dto.TenantConfigResponse, error)

	// UpdateTenantStatus 更新租户状态
	UpdateTenantStatus(ctx context.Context, tenantID string, status string) error

	// GetKeyRotationHistory 获取密钥轮换历史
	GetKeyRotationHistory(ctx context.Context, tenantID string) ([]*dto.KeyRotationHistory, error)
}

// tenantAppServiceImpl 租户应用服务实现
type tenantAppServiceImpl struct {
	tenantRepo    repository.TenantRepository
	cryptoService service.CryptoService
	logger        logger.Logger
}

// NewTenantAppService 创建租户应用服务实例
func NewTenantAppService(
	tenantRepo repository.TenantRepository,
	cryptoService service.CryptoService,
	logger logger.Logger,
) TenantAppService {
	return &tenantAppServiceImpl{
		tenantRepo:    tenantRepo,
		cryptoService: cryptoService,
		logger:        logger,
	}
}

// GetTenantConfig 获取租户配置
func (s *tenantAppServiceImpl) GetTenantConfig(ctx context.Context, tenantID string) (*dto.TenantConfigResponse, error) {
	s.logger.InfoContext(ctx, "Getting tenant config",
		"tenant_id", tenantID)

	// 从仓储获取租户配置
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NewNotFoundError("tenant", tenantID)
		}
		s.logger.ErrorContext(ctx, "Failed to get tenant config",
			"tenant_id", tenantID,
			"error", err)
		return nil, errors.Wrap(err, "failed to get tenant config")
	}

	// 转换为 DTO
	response := s.convertTenantToDTO(tenant)

	return response, nil
}

// UpdateTenantConfig 更新租户配置
func (s *tenantAppServiceImpl) UpdateTenantConfig(ctx context.Context, req *dto.UpdateTenantConfigRequest) error {
	s.logger.InfoContext(ctx, "Updating tenant config",
		"tenant_id", req.TenantID)

	// 验证请求参数
	if err := s.validateUpdateTenantConfigRequest(req); err != nil {
		return err
	}

	// 获取现有租户配置
	tenant, err := s.tenantRepo.FindByID(ctx, req.TenantID)
	if err != nil {
		if errors.IsNotFound(err) {
			return errors.NewNotFoundError("tenant", req.TenantID)
		}
		return errors.Wrap(err, "failed to get tenant")
	}

	// 更新配置
	if req.RateLimitConfig != nil {
		tenant.RateLimitConfig = *req.RateLimitConfig
	}
	if req.TokenTTLConfig != nil {
		tenant.TokenTTLConfig = *req.TokenTTLConfig
	}
	if req.KeyRotationPolicy != nil {
		tenant.KeyRotationPolicy = *req.KeyRotationPolicy
	}

	tenant.UpdatedAt = time.Now()

	// 保存更新
	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		s.logger.ErrorContext(ctx, "Failed to update tenant config",
			"tenant_id", req.TenantID,
			"error", err)
		return errors.Wrap(err, "failed to update tenant config")
	}

	s.logger.InfoContext(ctx, "Tenant config updated successfully",
		"tenant_id", req.TenantID)

	return nil
}

// RotateTenantKey 轮换租户密钥
func (s *tenantAppServiceImpl) RotateTenantKey(ctx context.Context, tenantID string, reason string) (*dto.KeyRotationResponse, error) {
	s.logger.InfoContext(ctx, "Starting tenant key rotation",
		"tenant_id", tenantID,
		"reason", reason)

	// 1. 获取租户配置
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, errors.NewNotFoundError("tenant", tenantID)
		}
		return nil, errors.Wrap(err, "failed to get tenant")
	}

	if tenant.Status != models.TenantStatusActive {
		return nil, errors.NewValidationError("tenant is not active")
	}

	// 2. 生成新密钥对
	s.logger.InfoContext(ctx, "Generating new key pair",
		"tenant_id", tenantID)

	newKeyID := fmt.Sprintf("tenant-key-%s-%d", tenantID, time.Now().Unix())
	privateKey, publicKey, err := s.cryptoService.GenerateKeyPair(ctx, 4096)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to generate key pair",
			"tenant_id", tenantID,
			"error", err)
		return nil, errors.Wrap(err, "failed to generate key pair")
	}

	// 3. 保存新密钥到 Vault
	s.logger.InfoContext(ctx, "Saving new key to Vault",
		"tenant_id", tenantID,
		"new_key_id", newKeyID)

	keyMetadata := &service.KeyMetadata{
		KeyID:     newKeyID,
		TenantID:  tenantID,
		Algorithm: "RS256",
		KeySize:   4096,
		CreatedAt: time.Now(),
		Status:    "active",
	}

	if err := s.cryptoService.StoreKeyPair(ctx, tenantID, newKeyID, privateKey, publicKey, keyMetadata); err != nil {
		s.logger.ErrorContext(ctx, "Failed to store key in Vault",
			"tenant_id", tenantID,
			"new_key_id", newKeyID,
			"error", err)
		return nil, errors.Wrap(err, "failed to store key in Vault")
	}

	// 4. 标记旧密钥为 deprecated
	oldKeyID := tenant.KeyRotationPolicy.ActiveKeyID
	if oldKeyID != "" {
		s.logger.InfoContext(ctx, "Marking old key as deprecated",
			"tenant_id", tenantID,
			"old_key_id", oldKeyID)

		if err := s.cryptoService.UpdateKeyStatus(ctx, tenantID, oldKeyID, "deprecated"); err != nil {
			s.logger.WarnContext(ctx, "Failed to mark old key as deprecated",
				"tenant_id", tenantID,
				"old_key_id", oldKeyID,
				"error", err)
			// 不返回错误，继续流程
		}
	}

	// 5. 更新数据库配置
	s.logger.InfoContext(ctx, "Updating tenant config in database",
		"tenant_id", tenantID,
		"new_key_id", newKeyID)

	tenant.KeyRotationPolicy.ActiveKeyID = newKeyID
	tenant.KeyRotationPolicy.LastRotatedAt = time.Now()
	tenant.KeyRotationPolicy.RotationReason = reason
	tenant.UpdatedAt = time.Now()

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		s.logger.ErrorContext(ctx, "Failed to update tenant config",
			"tenant_id", tenantID,
			"error", err)
		// 尝试回滚 Vault 中的密钥状态
		_ = s.cryptoService.UpdateKeyStatus(ctx, tenantID, newKeyID, "revoked")
		return nil, errors.Wrap(err, "failed to update tenant config")
	}

	// 6. 清除缓存
	s.logger.InfoContext(ctx, "Clearing public key cache",
		"tenant_id", tenantID)

	if err := s.cryptoService.ClearPublicKeyCache(ctx, tenantID); err != nil {
		s.logger.WarnContext(ctx, "Failed to clear public key cache",
			"tenant_id", tenantID,
			"error", err)
		// 不返回错误，缓存会自然过期
	}

	// 7. 记录审计日志
	s.logger.InfoContext(ctx, "Key rotation completed successfully",
		"tenant_id", tenantID,
		"old_key_id", oldKeyID,
		"new_key_id", newKeyID,
		"reason", reason)

	// 构造响应
	response := &dto.KeyRotationResponse{
		TenantID:     tenantID,
		OldKeyID:     oldKeyID,
		NewKeyID:     newKeyID,
		RotatedAt:    time.Now(),
		Reason:       reason,
		DeprecatedAt: time.Now().Add(30 * 24 * time.Hour), // 30 天后完全吊销
	}

	return response, nil
}

// ListTenants 列出所有租户
func (s *tenantAppServiceImpl) ListTenants(ctx context.Context, req *dto.ListTenantsRequest) (*dto.ListTenantsResponse, error) {
	s.logger.InfoContext(ctx, "Listing tenants",
		"page", req.Page,
		"page_size", req.PageSize,
		"status", req.Status)

	// 设置默认值
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 || req.PageSize > 100 {
		req.PageSize = 20
	}

	// 从仓储查询租户列表
	tenants, total, err := s.tenantRepo.List(ctx, req.Page, req.PageSize, req.Status)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to list tenants",
			"error", err)
		return nil, errors.Wrap(err, "failed to list tenants")
	}

	// 转换为 DTO
	tenantDTOs := make([]*dto.TenantConfigResponse, 0, len(tenants))
	for _, tenant := range tenants {
		tenantDTOs = append(tenantDTOs, s.convertTenantToDTO(tenant))
	}

	response := &dto.ListTenantsResponse{
		Tenants:  tenantDTOs,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}

	return response, nil
}

// CreateTenant 创建租户
func (s *tenantAppServiceImpl) CreateTenant(ctx context.Context, req *dto.CreateTenantRequest) (*dto.TenantConfigResponse, error) {
	s.logger.InfoContext(ctx, "Creating tenant",
		"tenant_name", req.TenantName)

	// 验证请求参数
	if err := s.validateCreateTenantRequest(req); err != nil {
		return nil, err
	}

	// 生成租户 ID
	tenantID := fmt.Sprintf("tenant-%d", time.Now().Unix())

	// 生成初始密钥对
	keyID := fmt.Sprintf("%s-key-001", tenantID)
	privateKey, publicKey, err := s.cryptoService.GenerateKeyPair(ctx, 4096)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate initial key pair")
	}

	// 保存密钥到 Vault
	keyMetadata := &service.KeyMetadata{
		KeyID:     keyID,
		TenantID:  tenantID,
		Algorithm: "RS256",
		KeySize:   4096,
		CreatedAt: time.Now(),
		Status:    "active",
	}

	if err := s.cryptoService.StoreKeyPair(ctx, tenantID, keyID, privateKey, publicKey, keyMetadata); err != nil {
		return nil, errors.Wrap(err, "failed to store initial key")
	}

	// 创建租户配置
	now := time.Now()
	tenant := &models.Tenant{
		TenantID:   tenantID,
		TenantName: req.TenantName,
		Status:     models.TenantStatusActive,
		RateLimitConfig: models.RateLimitConfig{
			GlobalQPS:  100000,
			TenantQPS:  50000,
			AgentQPS:   10,
			BurstSize:  200,
			WindowSize: 60,
		},
		TokenTTLConfig: models.TokenTTLConfig{
			RefreshTokenTTL: 2592000, // 30 天
			AccessTokenTTL:  900,     // 15 分钟
		},
		KeyRotationPolicy: models.KeyRotationPolicy{
			ActiveKeyID:       keyID,
			RotationIntervalDays: 90,
			LastRotatedAt:     now,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	// 保存到数据库
	if err := s.tenantRepo.Create(ctx, tenant); err != nil {
		s.logger.ErrorContext(ctx, "Failed to create tenant",
			"tenant_id", tenantID,
			"error", err)
		// 尝试清理 Vault 中的密钥
		_ = s.cryptoService.UpdateKeyStatus(ctx, tenantID, keyID, "revoked")
		return nil, errors.Wrap(err, "failed to create tenant")
	}

	s.logger.InfoContext(ctx, "Tenant created successfully",
		"tenant_id", tenantID,
		"tenant_name", req.TenantName)

	return s.convertTenantToDTO(tenant), nil
}

// UpdateTenantStatus 更新租户状态
func (s *tenantAppServiceImpl) UpdateTenantStatus(ctx context.Context, tenantID string, status string) error {
	s.logger.InfoContext(ctx, "Updating tenant status",
		"tenant_id", tenantID,
		"new_status", status)

	// 验证状态值
	validStatuses := map[string]bool{
		models.TenantStatusActive:    true,
		models.TenantStatusSuspended: true,
		models.TenantStatusDeleted:   true,
	}

	if !validStatuses[status] {
		return errors.NewValidationError(fmt.Sprintf("invalid status: %s", status))
	}

	// 获取租户
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID)
	if err != nil {
		if errors.IsNotFound(err) {
			return errors.NewNotFoundError("tenant", tenantID)
		}
		return errors.Wrap(err, "failed to get tenant")
	}

	// 更新状态
	tenant.Status = status
	tenant.UpdatedAt = time.Now()

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		s.logger.ErrorContext(ctx, "Failed to update tenant status",
			"tenant_id", tenantID,
			"error", err)
		return errors.Wrap(err, "failed to update tenant status")
	}

	s.logger.InfoContext(ctx, "Tenant status updated successfully",
		"tenant_id", tenantID,
		"new_status", status)

	return nil
}

// GetKeyRotationHistory 获取密钥轮换历史
func (s *tenantAppServiceImpl) GetKeyRotationHistory(ctx context.Context, tenantID string) ([]*dto.KeyRotationHistory, error) {
	s.logger.InfoContext(ctx, "Getting key rotation history",
		"tenant_id", tenantID)

	// 从 Vault 获取所有密钥
	keys, err := s.cryptoService.ListKeys(ctx, tenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to list keys",
			"tenant_id", tenantID,
			"error", err)
		return nil, errors.Wrap(err, "failed to list keys")
	}

	// 转换为历史记录
	history := make([]*dto.KeyRotationHistory, 0, len(keys))
	for _, key := range keys {
		history = append(history, &dto.KeyRotationHistory{
			KeyID:      key.KeyID,
			Status:     key.Status,
			CreatedAt:  key.CreatedAt,
			RotatedAt:  key.DeprecatedAt,
			RevokedAt:  key.RevokedAt,
			Algorithm:  key.Algorithm,
		})
	}

	return history, nil
}

// convertTenantToDTO 转换租户模型为 DTO
func (s *tenantAppServiceImpl) convertTenantToDTO(tenant *models.Tenant) *dto.TenantConfigResponse {
	return &dto.TenantConfigResponse{
		TenantID:   tenant.TenantID,
		TenantName: tenant.TenantName,
		Status:     tenant.Status,
		RateLimitConfig: dto.RateLimitConfig{
			GlobalQPS:  tenant.RateLimitConfig.GlobalQPS,
			TenantQPS:  tenant.RateLimitConfig.TenantQPS,
			AgentQPS:   tenant.RateLimitConfig.AgentQPS,
			BurstSize:  tenant.RateLimitConfig.BurstSize,
			WindowSize: tenant.RateLimitConfig.WindowSize,
		},
		TokenTTLConfig: dto.TokenTTLConfig{
			RefreshTokenTTL: tenant.TokenTTLConfig.RefreshTokenTTL,
			AccessTokenTTL:  tenant.TokenTTLConfig.AccessTokenTTL,
		},
		KeyRotationPolicy: dto.KeyRotationPolicy{
			ActiveKeyID:          tenant.KeyRotationPolicy.ActiveKeyID,
			RotationIntervalDays: tenant.KeyRotationPolicy.RotationIntervalDays,
			LastRotatedAt:        tenant.KeyRotationPolicy.LastRotatedAt,
		},
		CreatedAt: tenant.CreatedAt,
		UpdatedAt: tenant.UpdatedAt,
	}
}

// validateUpdateTenantConfigRequest 验证更新租户配置请求
func (s *tenantAppServiceImpl) validateUpdateTenantConfigRequest(req *dto.UpdateTenantConfigRequest) error {
	if req.TenantID == "" {
		return errors.NewValidationError("tenant_id is required")
	}

	if req.RateLimitConfig != nil {
		if req.RateLimitConfig.GlobalQPS <= 0 {
			return errors.NewValidationError("global_qps must be positive")
		}
		if req.RateLimitConfig.TenantQPS <= 0 {
			return errors.NewValidationError("tenant_qps must be positive")
		}
		if req.RateLimitConfig.AgentQPS <= 0 {
			return errors.NewValidationError("agent_qps must be positive")
		}
	}

	if req.TokenTTLConfig != nil {
		if req.TokenTTLConfig.RefreshTokenTTL <= 0 {
			return errors.NewValidationError("refresh_token_ttl must be positive")
		}
		if req.TokenTTLConfig.AccessTokenTTL <= 0 {
			return errors.NewValidationError("access_token_ttl must be positive")
		}
		if req.TokenTTLConfig.RefreshTokenTTL <= req.TokenTTLConfig.AccessTokenTTL {
			return errors.NewValidationError("refresh_token_ttl must be greater than access_token_ttl")
		}
	}

	if req.KeyRotationPolicy != nil {
		if req.KeyRotationPolicy.RotationIntervalDays < 30 {
			return errors.NewValidationError("rotation_interval_days must be at least 30")
		}
	}

	return nil
}

// validateCreateTenantRequest 验证创建租户请求
func (s *tenantAppServiceImpl) validateCreateTenantRequest(req *dto.CreateTenantRequest) error {
	if req.TenantName == "" {
		return errors.NewValidationError("tenant_name is required")
	}

	if len(req.TenantName) < 3 || len(req.TenantName) > 256 {
		return errors.NewValidationError("tenant_name must be between 3 and 256 characters")
	}

	return nil
}

//Personal.AI order the ending

