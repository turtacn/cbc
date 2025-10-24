package grpc

import (
	"context"
	"fmt"
	"time"

	authpb "github.com/turtacn/cbc/api/proto"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	domainService "github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthGRPCService gRPC 认证服务实现
type AuthGRPCService struct {
	authpb.UnimplementedAuthServiceServer
	authAppService service.AuthAppService
	cryptoService  domainService.CryptoService
	log            logger.Logger
}

// NewAuthGRPCService 创建 gRPC 认证服务
func NewAuthGRPCService(
	authAppService service.AuthAppService,
	cryptoService domainService.CryptoService,
	log logger.Logger,
) *AuthGRPCService {
	return &AuthGRPCService{
		authAppService: authAppService,
		cryptoService:  cryptoService,
		log:            log,
	}
}

// IssueToken 颁发令牌
func (s *AuthGRPCService) IssueToken(
	ctx context.Context,
	req *authpb.IssueTokenRequest,
) (*authpb.TokenResponse, error) {
	s.log.Info(ctx, "IssueToken request received",
		"tenant_id", req.TenantId,
		"device_id", req.DeviceId,
		"grant_type", req.GrantType,
	)

	// 转换 gRPC 请求为 DTO
	issueDTO := dto.IssueTokenRequest{
		TenantID:  req.TenantId,
		DeviceID:  req.DeviceId,
		GrantType: req.GrantType,
		Scope:     req.Scope,
		RequestID: req.RequestId,
	}

	// 处理客户端凭证
	if req.Credentials != nil {
		issueDTO.Credentials = &dto.ClientCredentials{
			ClientID:              req.Credentials.ClientId,
			ClientAssertionType:   req.Credentials.ClientAssertionType,
			ClientAssertion:       req.Credentials.ClientAssertion,
		}
	}

	// 处理设备信息
	if req.DeviceInfo != nil {
		issueDTO.DeviceInfo = &dto.DeviceInfo{
			DeviceFingerprint: req.DeviceInfo.DeviceFingerprint,
			OSType:            req.DeviceInfo.OsType,
			OSVersion:         req.DeviceInfo.OsVersion,
			DeviceModel:       req.DeviceInfo.DeviceModel,
			AppVersion:        req.DeviceInfo.AppVersion,
		}
	}

	// 调用应用服务
	tokenResp, err := s.authAppService.IssueToken(ctx, issueDTO)
	if err != nil {
		s.log.Error(ctx, "IssueToken failed",
			"tenant_id", req.TenantId,
			"device_id", req.DeviceId,
			"error", err,
		)
		return nil, err
	}

	// 转换为 gRPC 响应
	return &authpb.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
		IssuedAt:     tokenResp.IssuedAt,
		TenantId:     tokenResp.TenantID,
	}, nil
}

// RefreshToken 刷新令牌
func (s *AuthGRPCService) RefreshToken(
	ctx context.Context,
	req *authpb.RefreshTokenRequest,
) (*authpb.TokenResponse, error) {
	s.log.Info(ctx, "RefreshToken request received")

	// 转换 gRPC 请求为 DTO
	refreshDTO := dto.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
		Scope:        req.Scope,
		RequestID:    req.RequestId,
	}

	// 调用应用服务
	tokenResp, err := s.authAppService.RefreshToken(ctx, refreshDTO)
	if err != nil {
		s.log.Error(ctx, "RefreshToken failed", "error", err)
		return nil, err
	}

	return &authpb.TokenResponse{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		Scope:        tokenResp.Scope,
		IssuedAt:     tokenResp.IssuedAt,
		TenantId:     tokenResp.TenantID,
	}, nil
}

// RevokeToken 吊销令牌
func (s *AuthGRPCService) RevokeToken(
	ctx context.Context,
	req *authpb.RevokeTokenRequest,
) (*authpb.RevokeTokenResponse, error) {
	s.log.Info(ctx, "RevokeToken request received",
		"token_type_hint", req.TokenTypeHint,
		"reason", req.Reason,
	)

	// 转换 gRPC 请求为 DTO
	revokeDTO := dto.RevokeTokenRequest{
		Token:         req.Token,
		TokenTypeHint: req.TokenTypeHint,
		Reason:        req.Reason,
		OperatorID:    req.OperatorId,
	}

	// 调用应用服务
	revokeResp, err := s.authAppService.RevokeToken(ctx, revokeDTO)
	if err != nil {
		s.log.Error(ctx, "RevokeToken failed", "error", err)
		return &authpb.RevokeTokenResponse{
			Revoked:      false,
			ErrorMessage: err.Error(),
		}, nil
	}

	return &authpb.RevokeTokenResponse{
		Revoked:   revokeResp.Revoked,
		Jti:       revokeResp.JTI,
		RevokedAt: revokeResp.RevokedAt,
	}, nil
}

// VerifyToken 验证令牌
func (s *AuthGRPCService) VerifyToken(
	ctx context.Context,
	req *authpb.VerifyTokenRequest,
) (*authpb.VerifyTokenResponse, error) {
	s.log.Debug(ctx, "VerifyToken request received", "tenant_id", req.TenantId)

	// 验证 JWT 签名和有效期
	claims, err := s.cryptoService.VerifyJWT(ctx, req.Token, req.TenantId)
	if err != nil {
		s.log.Warn(ctx, "JWT verification failed", "error", err)
		return &authpb.VerifyTokenResponse{
			Valid:        false,
			ErrorCode:    getErrorCode(err),
			ErrorMessage: err.Error(),
		}, nil
	}

	// 检查黑名单(如果需要)
	if req.CheckBlacklist {
		isRevoked, err := s.authAppService.IsTokenRevoked(ctx, claims["jti"].(string))
		if err != nil {
			s.log.Error(ctx, "Failed to check blacklist", "error", err)
			return nil, status.Errorf(codes.Internal, "failed to check blacklist: %v", err)
		}
		if isRevoked {
			return &authpb.VerifyTokenResponse{
				Valid:        false,
				ErrorCode:    "token_revoked",
				ErrorMessage: "token has been revoked",
			}, nil
		}
	}

	// 转换 Claims 为 gRPC 响应
	tokenClaims := convertClaimsToProto(claims)

	return &authpb.VerifyTokenResponse{
		Valid:  true,
		Claims: tokenClaims,
	}, nil
}

// IntrospectToken 内省令牌(RFC 7662)
func (s *AuthGRPCService) IntrospectToken(
	ctx context.Context,
	req *authpb.IntrospectTokenRequest,
) (*authpb.IntrospectTokenResponse, error) {
	s.log.Debug(ctx, "IntrospectToken request received")

	// 验证调用方身份(如果提供了 client_id 和 client_secret)
	if req.ClientId != "" {
		// TODO: 验证调用方身份
	}

	// 解析 JWT 但不验证签名(用于内省)
	claims, err := s.cryptoService.ParseJWTWithoutVerify(ctx, req.Token)
	if err != nil {
		s.log.Warn(ctx, "JWT parsing failed", "error", err)
		return &authpb.IntrospectTokenResponse{
			Active: false,
		}, nil
	}

	// 检查令牌是否过期
	exp, ok := claims["exp"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return &authpb.IntrospectTokenResponse{
			Active: false,
		}, nil
	}

	// 检查黑名单
	jti, _ := claims["jti"].(string)
	isRevoked, err := s.authAppService.IsTokenRevoked(ctx, jti)
	if err != nil || isRevoked {
		return &authpb.IntrospectTokenResponse{
			Active: false,
		}, nil
	}

	// 构造内省响应
	scope, _ := claims["scope"].([]interface{})
	scopeStrings := make([]string, 0, len(scope))
	for _, s := range scope {
		if str, ok := s.(string); ok {
			scopeStrings = append(scopeStrings, str)
		}
	}

	metadata := make(map[string]string)
	if deviceTrustLevel, ok := claims["device_trust_level"].(string); ok {
		metadata["device_trust_level"] = deviceTrustLevel
	}

	return &authpb.IntrospectTokenResponse{
		Active:   true,
		Scope:    scopeStrings,
		ClientId: claims["client_id"].(string),
		TenantId: claims["tenant_id"].(string),
		TokenType: claims["token_type"].(string),
		Exp:      int64(exp),
		Iat:      int64(claims["iat"].(float64)),
		Sub:      claims["sub"].(string),
		Jti:      jti,
		Metadata: metadata,
	}, nil
}

// RegisterService 注册 gRPC 服务
func (s *AuthGRPCService) RegisterService(server *grpc.Server) {
	authpb.RegisterAuthServiceServer(server, s)
}

// convertClaimsToProto 将 JWT Claims 转换为 Protobuf TokenClaims
func convertClaimsToProto(claims map[string]interface{}) *authpb.TokenClaims {
	tokenClaims := &authpb.TokenClaims{}

	if iss, ok := claims["iss"].(string); ok {
		tokenClaims.Iss = iss
	}
	if sub, ok := claims["sub"].(string); ok {
		tokenClaims.Sub = sub
	}
	if aud, ok := claims["aud"].([]interface{}); ok {
		audStrings := make([]string, 0, len(aud))
		for _, a := range aud {
			if str, ok := a.(string); ok {
				audStrings = append(audStrings, str)
			}
		}
		tokenClaims.Aud = audStrings
	}
	if exp, ok := claims["exp"].(float64); ok {
		tokenClaims.Exp = int64(exp)
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		tokenClaims.Nbf = int64(nbf)
	}
	if iat, ok := claims["iat"].(float64); ok {
		tokenClaims.Iat = int64(iat)
	}
	if jti, ok := claims["jti"].(string); ok {
		tokenClaims.Jti = jti
	}
	if tenantID, ok := claims["tenant_id"].(string); ok {
		tokenClaims.TenantId = tenantID
	}
	if agentID, ok := claims["agent_id"].(string); ok {
		tokenClaims.AgentId = agentID
	}
	if scope, ok := claims["scope"].([]interface{}); ok {
		scopeStrings := make([]string, 0, len(scope))
		for _, s := range scope {
			if str, ok := s.(string); ok {
				scopeStrings = append(scopeStrings, str)
			}
		}
		tokenClaims.Scope = scopeStrings
	}
	if deviceTrustLevel, ok := claims["device_trust_level"].(string); ok {
		tokenClaims.DeviceTrustLevel = deviceTrustLevel
	}
	if tokenType, ok := claims["token_type"].(string); ok {
		tokenClaims.TokenType = tokenType
	}

	// 处理扩展元数据
	metadata := make(map[string]string)
	if meta, ok := claims["metadata"].(map[string]interface{}); ok {
		for k, v := range meta {
			if str, ok := v.(string); ok {
				metadata[k] = str
			}
		}
	}
	tokenClaims.Metadata = metadata

	return tokenClaims
}

// getErrorCode 获取错误代码
func getErrorCode(err error) string {
	switch {
	case errors.IsUnauthorized(err):
		return "unauthorized"
	case errors.IsInvalidInput(err):
		return "invalid_token"
	default:
		return "internal_error"
	}
}

//Personal.AI order the ending
