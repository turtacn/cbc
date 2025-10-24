package service

import (
	"context"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/pkg/utils"
)

// AuthAppService defines the interface for authentication-related application services.
type AuthAppService interface {
	IssueToken(ctx context.Context, req *dto.TokenIssueRequest) (*dto.TokenPairResponse, *errors.AppError)
	RefreshToken(ctx context.Context, req *dto.TokenRefreshRequest) (*dto.TokenPairResponse, *errors.AppError)
	RevokeToken(ctx context.Context, req *dto.TokenRevokeRequest) *errors.AppError
}

type authAppServiceImpl struct {
	tokenService  service.TokenService
	deviceRepo    repository.DeviceRepository
	tenantRepo    repository.TenantRepository
	rateLimiter   service.RateLimitService
	log           logger.Logger
}

// NewAuthAppService creates a new AuthAppService.
func NewAuthAppService(
	tokenService service.TokenService,
	deviceRepo repository.DeviceRepository,
	tenantRepo repository.TenantRepository,
	rateLimiter service.RateLimitService,
	log logger.Logger,
) AuthAppService {
	return &authAppServiceImpl{
		tokenService:  tokenService,
		deviceRepo:    deviceRepo,
		tenantRepo:    tenantRepo,
		rateLimiter:   rateLimiter,
		log:           log,
	}
}

// IssueToken handles the logic for issuing a new token pair.
func (s *authAppServiceImpl) IssueToken(ctx context.Context, req *dto.TokenIssueRequest) (*dto.TokenPairResponse, *errors.AppError) {
	// 1. Validate request
	if err := utils.ValidateStruct(req); err != nil {
		return nil, err
	}

	// 2. Check tenant
	tenant, err := s.tenantRepo.FindByID(ctx, req.TenantID)
	if err != nil {
		return nil, err
	}
	if !tenant.IsActive() {
		return nil, errors.ErrTenantInactive
	}

	// 3. Check rate limit
	allowed, err := s.rateLimiter.Allow(ctx, "tenant", req.TenantID.String())
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, errors.ErrRateLimitExceeded
	}

	// 4. Find or create device
	device, err := s.deviceRepo.FindByDeviceID(ctx, req.TenantID, req.DeviceID)
	if err != nil {
		// A more complete implementation would register the device here
		return nil, errors.ErrDeviceNotRegistered
	}

	// 5. Issue token pair
	access, refresh, err := s.tokenService.IssueTokenPair(ctx, tenant, device)
	if err != nil {
		return nil, err
	}

	// A more complete implementation would also create the string versions of the tokens
	return utils.TokenPairToDTO(access, refresh, "", ""), nil
}

// RefreshToken handles the logic for refreshing a token.
func (s *authAppServiceImpl) RefreshToken(ctx context.Context, req *dto.TokenRefreshRequest) (*dto.TokenPairResponse, *errors.AppError) {
	if err := utils.ValidateStruct(req); err != nil {
		return nil, err
	}

	access, refresh, err := s.tokenService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	// A more complete implementation would also create the string versions of the tokens
	return utils.TokenPairToDTO(access, refresh, "", ""), nil
}

// RevokeToken handles the logic for revoking a token.
func (s *authAppServiceImpl) RevokeToken(ctx context.Context, req *dto.TokenRevokeRequest) *errors.AppError {
	if err := utils.ValidateStruct(req); err != nil {
		return err
	}

	// A more complete implementation would parse the token to get the JTI
	jti := ""
	return s.tokenService.RevokeToken(ctx, jti)
}
//Personal.AI order the ending