package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/internal/infrastructure/monitoring"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/grpc"
	grpcCodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// InterceptorChain 拦截器链
type InterceptorChain struct {
	log              logger.Logger
	rateLimitService service.RateLimitService
	tracer           monitoring.TracingProvider
}

// NewInterceptorChain 创建拦截器链
func NewInterceptorChain(
	log logger.Logger,
	rateLimitService service.RateLimitService,
	tracer monitoring.TracingProvider,
) *InterceptorChain {
	return &InterceptorChain{
		log:              log,
		rateLimitService: rateLimitService,
		tracer:           tracer,
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
				ic.log.Error(ctx, "gRPC handler panic recovered",
					"method", info.FullMethod,
					"panic", r,
				)
				err = status.Errorf(grpcCodes.Internal, "internal server error: %v", r)
			}
		}()

		return handler(ctx, req)
	}
}

// UnaryTracingInterceptor 追踪拦截器(创建 Span)
func (ic *InterceptorChain) UnaryTracingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// 从 gRPC Metadata 提取 TraceID
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if traceIDs := md.Get("x-trace-id"); len(traceIDs) > 0 {
				ctx = context.WithValue(ctx, "trace_id", traceIDs[0])
			}
		}

		// 创建 Span
		ctx, span := ic.tracer.StartSpan(ctx, fmt.Sprintf("gRPC.%s", info.FullMethod))
		defer span.End()

		span.SetAttributes(
			attribute.String("rpc.system", "grpc"),
			attribute.String("rpc.service", info.FullMethod),
			attribute.String("rpc.method", info.FullMethod),
		)

		// 执行处理器
		resp, err := handler(ctx, req)

		// 记录结果
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "success")
		}

		return resp, err
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
			"method", info.FullMethod,
			"client_ip", clientIP,
			"user_agent", userAgent,
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
			"method", info.FullMethod,
			"duration_ms", duration.Milliseconds(),
			"status", statusCode.String(),
			"error", err,
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

		var identifier string
		if tenantIDs := md.Get("x-tenant-id"); len(tenantIDs) > 0 {
			identifier = fmt.Sprintf("tenant:%s", tenantIDs[0])
		} else if deviceIDs := md.Get("x-device-id"); len(deviceIDs) > 0 {
			identifier = fmt.Sprintf("device:%s", deviceIDs[0])
		} else {
			// 默认使用客户端 IP
			if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
				identifier = fmt.Sprintf("ip:%s", ips[0])
			} else {
				identifier = "global"
			}
		}

		// 检查限流
		allowed, err := ic.rateLimitService.Allow(ctx, identifier, info.FullMethod)
		if err != nil {
			ic.log.Error(ctx, "rate limit check failed",
				"identifier", identifier,
				"method", info.FullMethod,
				"error", err,
			)
			// 限流服务故障时降级放行
			return handler(ctx, req)
		}

		if !allowed {
			ic.log.Warn(ctx, "rate limit exceeded",
				"identifier", identifier,
				"method", info.FullMethod,
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
					"method", info.FullMethod,
					"error", err,
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
	switch {
	case errors.IsNotFound(err):
		return status.Errorf(grpcCodes.NotFound, err.Error())
	case errors.IsInvalidInput(err):
		return status.Errorf(grpcCodes.InvalidArgument, err.Error())
	case errors.IsUnauthorized(err):
		return status.Errorf(grpcCodes.Unauthenticated, err.Error())
	case errors.IsForbidden(err):
		return status.Errorf(grpcCodes.PermissionDenied, err.Error())
	case errors.IsConflict(err):
		return status.Errorf(grpcCodes.AlreadyExists, err.Error())
	case errors.IsRateLimitExceeded(err):
		return status.Errorf(grpcCodes.ResourceExhausted, err.Error())
	case errors.IsServiceUnavailable(err):
		return status.Errorf(grpcCodes.Unavailable, err.Error())
	default:
		return status.Errorf(grpcCodes.Internal, "internal server error: %v", err)
	}
}

// ChainUnaryInterceptors 链式调用所有拦截器
func (ic *InterceptorChain) ChainUnaryInterceptors() grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(
		ic.UnaryRecoveryInterceptor(),    // 1. 恢复 panic
		ic.UnaryTracingInterceptor(),     // 2. 追踪
		ic.UnaryLoggingInterceptor(),     // 3. 日志
		ic.UnaryRateLimitInterceptor(),   // 4. 限流
		ic.UnaryValidationInterceptor(),  // 5. 参数验证
		ic.UnaryErrorInterceptor(),       // 6. 错误转换
	)
}

//Personal.AI order the ending
