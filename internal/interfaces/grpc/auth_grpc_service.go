package grpc

import (
	"context"

	"github.com/google/uuid"
	pb "github.com/turtacn/cbc/api/proto"
	"github.com/turtacn/cbc/internal/application/dto"
	app_svc "github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthGRPCService implements the gRPC AuthService.
type AuthGRPCService struct {
	pb.UnimplementedAuthServiceServer
	authAppSvc service.AuthAppService
	cryptoSvc  service.CryptoService
	log        logger.Logger
}

// NewAuthGRPCServer creates a new gRPC server for the auth service.
func NewAuthGRPCServer(
	authAppSvc service.AuthAppService,
	cryptoSvc service.CryptoService,
	log logger.Logger,
	interceptors []grpc.UnaryServerInterceptor,
) *grpc.Server {

	server := grpc.NewServer(grpc.ChainUnaryInterceptor(interceptors...))
	pb.RegisterAuthServiceServer(server, &AuthGRPCService{
		authAppSvc: authAppSvc,
		cryptoSvc:  cryptoSvc,
		log:        log,
	})
	return server
}

// IssueToken handles the gRPC request to issue a token.
func (s *AuthGRPCService) IssueToken(ctx context.Context, req *pb.IssueTokenRequest) (*pb.TokenResponse, error) {
	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid tenant_id")
	}

	appReq := &dto.TokenIssueRequest{
		GrantType: req.GrantType,
		TenantID:  tenantID,
		DeviceID:  req.DeviceId,
	}

	resp, appErr := s.authAppSvc.IssueToken(ctx, appReq)
	if appErr != nil {
		return nil, status.Error(codes.Internal, appErr.Error())
	}

	return &pb.TokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.AccessTokenExpiresIn,
	}, nil
}

// RefreshToken handles the gRPC request to refresh a token.
func (s *AuthGRPCService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.TokenResponse, error) {
	appReq := &dto.TokenRefreshRequest{
		GrantType:    "refresh_token",
		RefreshToken: req.RefreshToken,
	}

	resp, appErr := s.authAppSvc.RefreshToken(ctx, appReq)
	if appErr != nil {
		return nil, status.Error(codes.Internal, appErr.Error())
	}

	return &pb.TokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.AccessTokenExpiresIn,
	}, nil
}

// RevokeToken handles the gRPC request to revoke a token.
func (s *AuthGRPCService) RevokeToken(ctx context.Context, req *pb.RevokeTokenRequest) (*pb.RevokeTokenResponse, error) {
	appReq := &dto.TokenRevokeRequest{Token: req.Token}
	if err := s.authAppSvc.RevokeToken(ctx, appReq); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &pb.RevokeTokenResponse{Success: true}, nil
}

// VerifyToken handles the gRPC request to verify a token.
func (s *AuthGRPCService) VerifyToken(ctx context.Context, req *pb.VerifyTokenRequest) (*pb.VerifyTokenResponse, error) {
	// A real implementation would parse tenantID from the token
	tenantID := uuid.New()
	claims, err := s.cryptoSvc.VerifyJWT(ctx, req.Token, tenantID)
	if err != nil {
		return &pb.VerifyTokenResponse{Valid: false}, nil
	}

	// A real implementation would convert claims to a protobuf struct
	return &pb.VerifyTokenResponse{Valid: true}, nil
}
//Personal.AI order the ending