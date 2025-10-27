package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"google.golang.org/grpc"
	grpcCodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// InterceptorChain 拦截器链
type InterceptorChain struct {
	log              logger.Logger
	rateLimitService service.RateLimitService
}

// NewInterceptorChain 创建拦截器链
func NewInterceptorChain(
	log logger.Logger,
	rateLimitService service.RateLimitService,
) *InterceptorChain {
	return &InterceptorChain{
		log:              log,
		rateLimitService: rateLimitService,
	}
}

// UnaryRecoveryInterceptor 恢复拦截器(捕获 panic)
func (ic *InterceptorChain) UnaryRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				ic.log.Error(ctx, "gRPC handler panic recovered", fmt.Errorf("%v", r),
					logger.String("method", info.FullMethod),
				)
				err = status.Errorf(grpcCodes.Internal, "internal server error: %v", r)
			}
		}()

		return handler(ctx, req)
	}
}

// UnaryLoggingInterceptor 日志拦截器
func (ic *InterceptorChain) UnaryLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		startTime := time.Now()

		// 提取 Metadata
		md, _ := metadata.FromIncomingContext(ctx)
		var clientIP, userAgent string
		if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			clientIP = ips[0]
		}
		if agents := md.Get("user-agent"); len(agents) > 0 {
			userAgent = agents[0]
		}

		ic.log.Info(ctx, "gRPC request received",
			logger.String("method", info.FullMethod),
			logger.String("client_ip", clientIP),
			logger.String("user_agent", userAgent),
		)

		// 执行处理器
		resp, err := handler(ctx, req)

		duration := time.Since(startTime)
		statusCode := grpcCodes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				statusCode = st.Code()
			}
		}

		ic.log.Info(ctx, "gRPC request completed",
			logger.String("method", info.FullMethod),
			logger.Int64("duration_ms", duration.Milliseconds()),
			logger.String("status", statusCode.String()),
		)

		return resp, err
	}
}

// UnaryRateLimitInterceptor 限流拦截器
func (ic *InterceptorChain) UnaryRateLimitInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// 提取客户端标识符(tenant_id, device_id 等)
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(grpcCodes.InvalidArgument, "missing metadata")
		}

		var dimension service.RateLimitDimension
		var identifier string
		if tenantIDs := md.Get("x-tenant-id"); len(tenantIDs) > 0 {
			dimension = service.RateLimitDimensionTenant
			identifier = tenantIDs[0]
		} else if deviceIDs := md.Get("x-device-id"); len(deviceIDs) > 0 {
			dimension = service.RateLimitDimensionDevice
			identifier = deviceIDs[0]
		} else {
			// 默认使用客户端 IP
			if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
				dimension = service.RateLimitDimensionIP
				identifier = ips[0]
			} else {
				dimension = service.RateLimitDimensionGlobal
				identifier = "global"
			}
		}

		// 检查限流
		allowed, _, _, err := ic.rateLimitService.Allow(ctx, dimension, identifier, info.FullMethod)
		if err != nil {
			ic.log.Error(ctx, "rate limit check failed", err,
				logger.String("identifier", identifier),
				logger.String("method", info.FullMethod),
			)
			// 限流服务故障时降级放行
			return handler(ctx, req)
		}

		if !allowed {
			ic.log.Warn(ctx, "rate limit exceeded",
				logger.String("identifier", identifier),
				logger.String("method", info.FullMethod),
			)
			return nil, status.Errorf(
				grpcCodes.ResourceExhausted,
				"rate limit exceeded for %s",
				identifier,
			)
		}

		return handler(ctx, req)
	}
}

// UnaryValidationInterceptor 参数验证拦截器
func (ic *InterceptorChain) UnaryValidationInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// 如果请求实现了 Validator 接口,执行验证
		if validator, ok := req.(interface{ Validate() error }); ok {
			if err := validator.Validate(); err != nil {
				ic.log.Warn(ctx, "request validation failed",
					logger.String("method", info.FullMethod),
				)
				return nil, status.Errorf(grpcCodes.InvalidArgument, "validation failed: %v", err)
			}
		}

		return handler(ctx, req)
	}
}

// UnaryErrorInterceptor 错误转换拦截器(将领域错误转换为 gRPC 状态码)
func (ic *InterceptorChain) UnaryErrorInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		resp, err := handler(ctx, req)
		if err == nil {
			return resp, nil
		}

		// 转换领域错误为 gRPC 状态码
		return resp, convertDomainErrorToGRPC(err)
	}
}

// convertDomainErrorToGRPC 将领域错误转换为 gRPC 错误
func convertDomainErrorToGRPC(err error) error {
	cbcErr, ok := errors.AsCBCError(err)
	if !ok {
		return status.Errorf(grpcCodes.Internal, "internal server error: %v", err)
	}

	switch cbcErr.HTTPStatus() {
	case 404:
		return status.Errorf(grpcCodes.NotFound, "%s", cbcErr.Error())
	case 400:
		return status.Errorf(grpcCodes.InvalidArgument, "%s", cbcErr.Error())
	case 401:
		return status.Errorf(grpcCodes.Unauthenticated, "%s", cbcErr.Error())
	case 403:
		return status.Errorf(grpcCodes.PermissionDenied, "%s", cbcErr.Error())
	case 409:
		return status.Errorf(grpcCodes.AlreadyExists, "%s", cbcErr.Error())
	case 429:
		return status.Errorf(grpcCodes.ResourceExhausted, "%s", cbcErr.Error())
	case 503:
		return status.Errorf(grpcCodes.Unavailable, "%s", cbcErr.Error())
	default:
		return status.Errorf(grpcCodes.Internal, "internal server error: %v", err)
	}
}

// ChainUnaryInterceptors 链式调用所有拦截器
func (ic *InterceptorChain) ChainUnaryInterceptors() grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(
		ic.UnaryRecoveryInterceptor(),    // 1. 恢复 panic
		ic.UnaryLoggingInterceptor(),     // 2. 日志
		ic.UnaryRateLimitInterceptor(),   // 3. 限流
		ic.UnaryValidationInterceptor(),  // 4. 参数验证
		ic.UnaryErrorInterceptor(),       // 5. 错误转换
	)
}
