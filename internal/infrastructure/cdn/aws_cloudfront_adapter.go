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

// CloudFrontClient defines the interface for the CloudFront client, allowing for mocking.
type CloudFrontClient interface {
	CreateInvalidation(ctx context.Context, params *cloudfront.CreateInvalidationInput, optFns ...func(*cloudfront.Options)) (*cloudfront.CreateInvalidationOutput, error)
}

// AWSCloudFrontAdapter implements the CDNCacheManager for AWS CloudFront.
type AWSCloudFrontAdapter struct {
	client         CloudFrontClient
	distributionID string
	logger         logger.Logger
}

// NewAWSCloudFrontAdapter creates a new AWSCloudFrontAdapter.
// It initializes an AWS session and a CloudFront client.
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

// NewAWSCloudFrontAdapterWithClient creates a new AWSCloudFrontAdapter with a specific client.
// This is useful for testing with a mock client.
func NewAWSCloudFrontAdapterWithClient(client CloudFrontClient, distributionID string, log logger.Logger) service.CDNCacheManager {
	return &AWSCloudFrontAdapter{
		client:         client,
		distributionID: distributionID,
		logger:         log.WithComponent("AWSCloudFrontAdapter"),
	}
}

// PurgeTenantJWKS constructs the specific path for a tenant's JWKS and purges it.
func (a *AWSCloudFrontAdapter) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	path := fmt.Sprintf("/api/v1/auth/jwks/%s", tenantID)
	return a.PurgePath(ctx, path)
}

// PurgePath sends an invalidation request to CloudFront for the given path.
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
