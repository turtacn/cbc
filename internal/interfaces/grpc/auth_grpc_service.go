package grpc

import (
	"context"

	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	authpb "github.com/turtacn/cbc/internal/interfaces/grpc/proto"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"strings"
)

// AuthGRPCService provides the gRPC implementation of the authentication service.
// It acts as an adapter, translating gRPC requests to application service calls and mapping results back to gRPC responses.
// AuthGRPCService 提供了认证服务的 gRPC 实现。
// 它充当适配器，将 gRPC 请求转换为应用程序服务调用，并将结果映射回 gRPC 响应。
type AuthGRPCService struct {
	authpb.UnimplementedAuthServiceServer
	authAppService service.AuthAppService
	log            logger.Logger
}

// NewAuthGRPCService creates a new instance of the AuthGRPCService.
// NewAuthGRPCService 创建一个新的 AuthGRPCService 实例。
func NewAuthGRPCService(
	authAppService service.AuthAppService,
	log logger.Logger,
) *AuthGRPCService {
	return &AuthGRPCService{
		authAppService: authAppService,
		log:            log,
	}
}

// IssueToken handles the gRPC request for issuing a new token.
// It converts the protobuf request into a DTO, calls the application service, and formats the response.
// IssueToken 处理颁发新令牌的 gRPC 请求。
// 它将 protobuf 请求转换为 DTO, 调用应用程序服务, 并格式化响应。
func (s *AuthGRPCService) IssueToken(
	ctx context.Context,
	req *authpb.IssueTokenRequest,
) (*authpb.TokenResponse, error) {
	s.log.Info(ctx, "IssueToken request received via gRPC",
		logger.String("tenant_id", req.TenantId),
		logger.String("grant_type", req.GrantType),
	)

	// Convert gRPC request to DTO
	issueDTO := &dto.TokenIssueRequest{
		TenantID:     req.TenantId,
		GrantType:    req.GrantType,
		Scope:        strings.Join(req.Scope, " "),
		AgentID:      req.DeviceId,
		DeviceInfo:   req.DeviceInfo.String(),
		ClientID:     req.Credentials.ClientId,
		ClientSecret: req.Credentials.ClientAssertion,
	}

	// Call the application service
	tokenResp, err := s.authAppService.IssueToken(ctx, issueDTO)
	if err != nil {
		s.log.Error(ctx, "IssueToken failed in application service", err,
			logger.String("tenant_id", req.TenantId),
		)
		return nil, mapDomainErrToGRPC(err)
	}

	// Convert DTO response to gRPC response
	return &authpb.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        strings.Split(tokenResp.Scope, " "),
		IssuedAt:     tokenResp.IssuedAt,
	}, nil
}

// RevokeToken handles the gRPC request for revoking a token.
// It converts the protobuf request into a DTO and calls the application service.
// RevokeToken 处理撤销令牌的 gRPC 请求。
// 它将 protobuf 请求转换为 DTO 并调用应用程序服务。
func (s *AuthGRPCService) RevokeToken(ctx context.Context, req *authpb.RevokeTokenRequest) (*authpb.RevokeTokenResponse, error) {
	s.log.Info(ctx, "RevokeToken request received via gRPC")

	revokeDTO := &dto.RevokeTokenRequest{
		Token:         req.Token,
		TokenTypeHint: req.TokenTypeHint,
		Reason:        req.Reason,
	}

	err := s.authAppService.RevokeToken(ctx, revokeDTO)
	if err != nil {
		s.log.Error(ctx, "RevokeToken failed in application service", err)
		return nil, mapDomainErrToGRPC(err)
	}

	return &authpb.RevokeTokenResponse{
		Revoked: true,
	}, nil
}

// mapDomainErrToGRPC translates domain-specific errors into standard gRPC status errors.
// This ensures that clients receive meaningful, standardized error codes.
// mapDomainErrToGRPC 将特定领域的错误转换为标准的 gRPC 状态错误。
// 这确保客户端接收到有意义的、标准化的错误代码。
func mapDomainErrToGRPC(err error) error {
	if e, ok := err.(errors.CBCError); ok {
		switch e.Code() {
		case errors.ErrCodeInvalidRequest:
			return status.Error(codes.InvalidArgument, e.Description())
		case errors.ErrCodeUnauthorized, errors.CodeUnauthenticated:
			return status.Error(codes.Unauthenticated, e.Description())
		case errors.ErrCodeForbidden:
			return status.Error(codes.PermissionDenied, e.Description())
		case errors.ErrCodeNotFound:
			return status.Error(codes.NotFound, e.Description())
		case errors.ErrCodeConflict:
			return status.Error(codes.AlreadyExists, e.Description())
		case errors.ErrCodeRateLimitExceeded:
			return status.Error(codes.ResourceExhausted, e.Description())
		default:
			return status.Error(codes.Internal, "An unexpected internal error occurred")
		}
	}
	// Fallback for non-domain errors
	return status.Error(codes.Internal, "An unexpected error occurred")
}
