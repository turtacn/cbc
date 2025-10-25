package service

import (
	"context"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/repository"
	domainsvc "github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// AuthAppService defines the interface for authentication-related application services.
type AuthAppService interface {
	IssueToken(ctx context.Context, req *dto.TokenIssueRequest) (*dto.TokenPairResponse, *errors.AppError)
	RevokeToken(ctx context.Context, req *dto.TokenRevokeRequest) *errors.AppError
	RefreshToken(ctx context.Context, req *dto.TokenRefreshRequest) (*dto.TokenPairResponse, *errors.AppError)
	// (其他方法略)
}

type authAppServiceImpl struct {
	tenantRepo   repository.TenantRepository
	deviceRepo   repository.DeviceRepository
	tokenService domainsvc.TokenService
	rateLimiter  domainsvc.RateLimitService
	logger       logger.Logger
}

func NewAuthAppService(
	tenantRepo repository.TenantRepository,
	deviceRepo repository.DeviceRepository,
	tokenService domainsvc.TokenService,
	rateLimiter domainsvc.RateLimitService,
	l logger.Logger,
) AuthAppService {
	return &authAppServiceImpl{
		tenantRepo:   tenantRepo,
		deviceRepo:   deviceRepo,
		tokenService: tokenService,
		rateLimiter:  rateLimiter,
		logger:       l,
	}
}

func (s *authAppServiceImpl) IssueToken(ctx context.Context, req *dto.TokenIssueRequest) (*dto.TokenPairResponse, *errors.AppError) {
	// 1. 输入校验
	if req == nil {
		return nil, errors.ErrInvalidArgument
	}
	if err := utils.ValidateStruct(req); err != nil {
		return nil, err
	}

	// 2. 校验租户
	tenant, appErr := s.tenantRepo.FindByID(ctx, req.TenantID)
	if appErr != nil {
		return nil, appErr
	}
	if tenant == nil || !tenant.IsActive() {
		return nil, errors.ErrTenantInactive
	}

	// 3. rate limit 校验（按租户/设备）
	allowed, rlErr := s.rateLimiter.Allow(ctx, constants.RateLimitScopeTenant, req.TenantID.String())
	if rlErr != nil {
		// 若限流服务出错，按保守策略拒绝或允许：这里选择拒绝并记录错误
		s.logger.Warn(ctx, "rate limiter check failed", logger.Fields{"error": rlErr.Error()})
		return nil, rlErr
	}
	if !allowed {
		return nil, errors.ErrTooManyRequests
	}

	// 4. 设备校验（若需要）
	// 若设备数据是 uuid 存储，简单示例不强制转换
	// device, dErr := s.deviceRepo.FindByID(ctx, req.DeviceID)
	// if dErr != nil { return nil, dErr }

	// 5. 调用 domain token service 颁发 token pair
	accessToken, refreshToken, tErr := s.tokenService.IssueTokenPair(ctx, tenant, &models.Device{
		// 假设设备模型最少有 ID 字段，这里以字符串转 UUID 尝试，如果失败使用新 UUID
		DeviceID: req.DeviceID,
	})
	if tErr != nil {
		s.logger.Error(ctx, "token service issue failed", tErr)
		return nil, tErr
	}

	// 6. 转换 DTO 返回
	resp := &dto.TokenPairResponse{
		AccessToken:           accessToken.TokenString(),
		RefreshToken:          refreshToken.TokenString(),
		AccessTokenExpiresIn:  accessToken.ExpiresInSeconds(),
		RefreshTokenExpiresIn: refreshToken.ExpiresInSeconds(),
		TokenType:             "Bearer",
	}
	return resp, nil
}

func (s *authAppServiceImpl) RevokeToken(ctx context.Context, req *dto.TokenRevokeRequest) *errors.AppError {
	if req == nil {
		return errors.ErrInvalidArgument
	}
	if err := utils.ValidateStruct(req); err != nil {
		return err
	}

	// 解析 token 获取 jti（此处交给 tokenService 或 cryptoService）
	jti, err := utils.ExtractJTIFromToken(req.Token)
	if err != nil {
		return errors.ErrInvalidArgument
	}
	return s.tokenService.RevokeToken(ctx, jti)
}

func (s *authAppServiceImpl) RefreshToken(ctx context.Context, req *dto.TokenRefreshRequest) (*dto.TokenPairResponse, *errors.AppError) {
	return nil, nil
}
