package grpc

import (
	"context"
	goerrors "errors"
	"time"

	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryLoggingInterceptor logs unary gRPC requests.
func UnaryLoggingInterceptor(log logger.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		latency := time.Since(start)

		log.Info(ctx, "gRPC request processed", logger.Fields{
			"method":     info.FullMethod,
			"latency_ms": latency.Milliseconds(),
			"status":     status.Code(err),
		})
		return resp, err
	}
}

// UnaryRecoveryInterceptor recovers from panics in gRPC handlers.
func UnaryRecoveryInterceptor(log logger.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		defer func() {
			if err := recover(); err != nil {
				log.Error(ctx, "Panic recovered in gRPC handler", goerrors.New("panic"), logger.Fields{"panic": err})
			}
		}()
		return handler(ctx, req)
	}
}

// UnaryTracingInterceptor adds tracing to gRPC requests.
func UnaryTracingInterceptor() grpc.UnaryServerInterceptor {
	// A real implementation would extract trace context from gRPC metadata
	// and create a span.
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		return handler(ctx, req)
	}
}

// UnaryRateLimitInterceptor applies rate limiting to gRPC requests.
func UnaryRateLimitInterceptor(limiter service.RateLimitService) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// A real implementation would get an identifier from the request metadata
		identifier := "grpc_client"
		allowed, err := limiter.Allow(ctx, constants.RateLimitScopeGlobal, identifier)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		if !allowed {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

//Personal.AI order the ending
