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

// InterceptorChain holds the dependencies required for the gRPC interceptors.
// It provides a centralized way to manage and configure the interceptors.
// InterceptorChain 保存 gRPC 拦截器所需的依赖项。
// 它提供了一种集中管理和配置拦截器的方法。
type InterceptorChain struct {
	log              logger.Logger
	rateLimitService service.RateLimitService
}

// NewInterceptorChain creates a new InterceptorChain with the necessary dependencies.
// NewInterceptorChain 使用必要的依赖项创建一个新的 InterceptorChain。
func NewInterceptorChain(
	log logger.Logger,
	rateLimitService service.RateLimitService,
) *InterceptorChain {
	return &InterceptorChain{
		log:              log,
		rateLimitService: rateLimitService,
	}
}

// UnaryRecoveryInterceptor is a gRPC unary interceptor that recovers from panics in handlers.
// It logs the panic and returns a standard gRPC 'Internal' error to the client.
// UnaryRecoveryInterceptor 是一个 gRPC 一元拦截器，可从处理器中的 panic 中恢复。
// 它会记录 panic 并向客户端返回一个标准的 gRPC 'Internal' 错误。
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

// UnaryLoggingInterceptor is a gRPC unary interceptor that logs incoming requests and their outcomes.
// It logs metadata such as the method, client IP, user agent, duration, and final status code.
// UnaryLoggingInterceptor 是一个 gRPC 一元拦截器，用于记录传入的请求及其结果。
// 它记录元数据，例如方法、客户端 IP、用户代理、持续时间和最终状态代码。
func (ic *InterceptorChain) UnaryLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		startTime := time.Now()

		// Extract metadata from the incoming context
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

		// Execute the handler
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

// UnaryRateLimitInterceptor is a gRPC unary interceptor that enforces rate limits.
// It identifies the client by tenant ID, device ID, or IP address and checks with the rate limit service.
// If the limit is exceeded, it returns a 'ResourceExhausted' error.
// UnaryRateLimitInterceptor 是一个强制执行速率限制的 gRPC 一元拦截器。
// 它通过租户 ID、设备 ID 或 IP 地址识别客户端，并与速率限制服务核对。
// 如果超出限制，它将返回“ResourceExhausted”错误。
func (ic *InterceptorChain) UnaryRateLimitInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Extract client identifier from metadata
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
			// Fallback to client IP
			if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
				dimension = service.RateLimitDimensionIP
				identifier = ips[0]
			} else {
				dimension = service.RateLimitDimensionGlobal
				identifier = "global"
			}
		}

		// Check rate limit
		allowed, _, _, err := ic.rateLimitService.Allow(ctx, dimension, identifier, info.FullMethod)
		if err != nil {
			ic.log.Error(ctx, "rate limit check failed", err,
				logger.String("identifier", identifier),
				logger.String("method", info.FullMethod),
			)
			// Degrade gracefully by allowing the request if the rate limit service fails
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

// UnaryValidationInterceptor is a gRPC unary interceptor that validates incoming request messages.
// It checks if the request object implements a `Validate() error` method and, if so, executes it.
// UnaryValidationInterceptor 是一个 gRPC 一元拦截器，用于验证传入的请求消息。
// 它检查请求对象是否实现了 `Validate() error` 方法，如果实现了，则执行该方法。
func (ic *InterceptorChain) UnaryValidationInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// If the request implements the Validator interface, validate it.
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

// UnaryErrorInterceptor is a gRPC unary interceptor that converts domain-specific errors into gRPC status codes.
// This ensures a consistent error-handling layer between the domain and the transport.
// UnaryErrorInterceptor 是一个 gRPC 一元拦截器，可将特定于域的错误转换为 gRPC 状态代码。
// 这确保了域和传输之间的错误处理层保持一致。
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

		// Convert domain errors to gRPC status codes
		return resp, convertDomainErrorToGRPC(err)
	}
}

// convertDomainErrorToGRPC is a helper function that maps custom domain errors to standard gRPC status errors.
// convertDomainErrorToGRPC 是一个辅助函数，可将自定义域错误映射到标准 gRPC 状态错误。
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

// ChainUnaryInterceptors combines all unary interceptors into a single `grpc.ServerOption`.
// The order is important: recovery is first, followed by logging, rate limiting, validation, and finally error conversion.
// ChainUnaryInterceptors 将所有一元拦截器组合成一个 `grpc.ServerOption`。
// 顺序很重要：首先是恢复，然后是日志记录、速率限制、验证，最后是错误转换。
func (ic *InterceptorChain) ChainUnaryInterceptors() grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(
		ic.UnaryRecoveryInterceptor(),    // 1. Recover from panics
		ic.UnaryLoggingInterceptor(),     // 2. Log request/response
		ic.UnaryRateLimitInterceptor(),   // 3. Enforce rate limits
		ic.UnaryValidationInterceptor(),  // 4. Validate request parameters
		ic.UnaryErrorInterceptor(),       // 5. Convert domain errors
	)
}
