// Package cdn provides CDN cache management adapters.
//go:build !test
package cdn

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/google/uuid"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// CloudFrontClient defines the interface for the AWS CloudFront client's CreateInvalidation method.
// This allows for mocking the AWS SDK client in tests.
// CloudFrontClient 定义了 AWS CloudFront 客户端的 CreateInvalidation 方法的接口。
// 这允许在测试中模拟 AWS SDK 客户端。
type CloudFrontClient interface {
	CreateInvalidation(ctx context.Context, params *cloudfront.CreateInvalidationInput, optFns ...func(*cloudfront.Options)) (*cloudfront.CreateInvalidationOutput, error)
}

// AWSCloudFrontAdapter implements the CDNCacheManager interface for AWS CloudFront.
// It handles creating and sending cache invalidation requests to a specific CloudFront distribution.
// AWSCloudFrontAdapter 为 AWS CloudFront 实现了 CDNCacheManager 接口。
// 它处理创建缓存失效请求并将其发送到特定的 CloudFront 分发。
type AWSCloudFrontAdapter struct {
	client         CloudFrontClient
	distributionID string
	logger         logger.Logger
}

// NewAWSCloudFrontAdapter creates a new AWSCloudFrontAdapter.
// It initializes the official AWS SDK config and a CloudFront client.
// NewAWSCloudFrontAdapter 创建一个新的 AWSCloudFrontAdapter。
// 它会初始化官方的 AWS SDK 配置和 CloudFront 客户端。
func NewAWSCloudFrontAdapter(ctx context.Context, distributionID string, log logger.Logger) (service.CDNCacheManager, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	client := cloudfront.NewFromConfig(cfg)

	return &AWSCloudFrontAdapter{
		client:         client,
		distributionID: distributionID,
		logger:         log.WithComponent("AWSCloudFrontAdapter"),
	}, nil
}

// NewAWSCloudFrontAdapterWithClient creates a new AWSCloudFrontAdapter using a provided client.
// This constructor is useful for testing with a mock client.
// NewAWSCloudFrontAdapterWithClient 使用提供的客户端创建一个新的 AWSCloudFrontAdapter。
// 这个构造函数对于使用模拟客户端进行测试很有用。
func NewAWSCloudFrontAdapterWithClient(client CloudFrontClient, distributionID string, log logger.Logger) service.CDNCacheManager {
	return &AWSCloudFrontAdapter{
		client:         client,
		distributionID: distributionID,
		logger:         log.WithComponent("AWSCloudFrontAdapter"),
	}
}

// PurgeTenantJWKS constructs the specific path for a tenant's JWKS endpoint and initiates a cache purge.
// This is typically called after a key rotation.
// PurgeTenantJWKS 为租户的 JWKS 端点构造特定路径并发起缓存清除。
// 这通常在密钥轮换后调用。
func (a *AWSCloudFrontAdapter) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	path := fmt.Sprintf("/api/v1/auth/jwks/%s", tenantID)
	return a.PurgePath(ctx, path)
}

// PurgePath sends a cache invalidation request to the configured CloudFront distribution for the specified path.
// It generates a unique caller reference for each invalidation to ensure idempotency.
// PurgePath 将指定路径的缓存失效请求发送到配置的 CloudFront 分发。
// 它为每次失效生成一个唯一的调用者引用，以确保幂等性。
func (a *AWSCloudFrontAdapter) PurgePath(ctx context.Context, path string) error {
	callerReference := uuid.NewString()

	input := &cloudfront.CreateInvalidationInput{
		DistributionId: &a.distributionID,
		InvalidationBatch: &types.InvalidationBatch{
			CallerReference: &callerReference,
			Paths: &types.Paths{
				Quantity: &[]int32{1}[0],
				Items:    []string{path},
			},
		},
	}

	_, err := a.client.CreateInvalidation(ctx, input)
	if err != nil {
		a.logger.Error(ctx, "failed to create cloudfront invalidation", err, logger.String("path", path))
		return fmt.Errorf("failed to create cloudfront invalidation for path %s: %w", path, err)
	}

	a.logger.Info(ctx, "successfully created cloudfront invalidation", logger.String("path", path))
	return nil
}
