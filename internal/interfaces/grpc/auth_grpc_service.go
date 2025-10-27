package grpc

import (
	"context"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	authpb "github.com/turtacn/cbc/internal/interfaces/grpc/proto"
	"github.com/turtacn/cbc/pkg/logger"
	"strings"
)

// AuthGRPCService gRPC 认证服务实现
type AuthGRPCService struct {
	authpb.UnimplementedAuthServiceServer
	authAppService service.AuthAppService
	log            logger.Logger
}

// NewAuthGRPCService 创建 gRPC 认证服务
func NewAuthGRPCService(
	authAppService service.AuthAppService,
	log logger.Logger,
) *AuthGRPCService {
	return &AuthGRPCService{
		authAppService: authAppService,
		log:            log,
	}
}

// IssueToken 颁发令牌
func (s *AuthGRPCService) IssueToken(
	ctx context.Context,
	req *authpb.IssueTokenRequest,
) (*authpb.TokenResponse, error) {
	s.log.Info(ctx, "IssueToken request received",
		logger.String("tenant_id", req.TenantId),
		logger.String("grant_type", req.GrantType),
	)

	// 转换 gRPC 请求为 DTO
	issueDTO := &dto.TokenIssueRequest{
		TenantID:     req.TenantId,
		GrantType:    req.GrantType,
		Scope:        strings.Join(req.Scope, " "),
		AgentID:      req.DeviceId,
		DeviceInfo:   req.DeviceInfo.String(),
		ClientID:     req.Credentials.ClientId,
		ClientSecret: req.Credentials.ClientAssertion,
	}

	// 调用应用服务
	tokenResp, err := s.authAppService.IssueToken(ctx, issueDTO)
	if err != nil {
		s.log.Error(ctx, "IssueToken failed", err,
			logger.String("tenant_id", req.TenantId),
		)
		return nil, err
	}

	// 转换为 gRPC 响应
	return &authpb.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        strings.Split(tokenResp.Scope, " "),
		IssuedAt:     tokenResp.IssuedAt,
	}, nil
}
