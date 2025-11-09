//go:build unit

package tests

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/infrastructure/cdn"
	"github.com/turtacn/cbc/pkg/logger"
)

// MockCloudFrontClient is a mock of the CloudFront client for testing.
type MockCloudFrontClient struct {
	mock.Mock
}

func (m *MockCloudFrontClient) CreateInvalidation(ctx context.Context, params *cloudfront.CreateInvalidationInput, optFns ...func(*cloudfront.Options)) (*cloudfront.CreateInvalidationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*cloudfront.CreateInvalidationOutput), args.Error(1)
}

// TestAWSCloudFrontAdapter_PurgeTenantJWKS tests the PurgeTenantJWKS method.
func TestAWSCloudFrontAdapter_PurgeTenantJWKS(t *testing.T) {
	mockClient := new(MockCloudFrontClient)
	log := logger.NewNoopLogger()
	distributionID := "E123ABC456DEF"

	adapter := cdn.NewAWSCloudFrontAdapterWithClient(mockClient, distributionID, log)

	tenantID := "test-tenant"
	path := fmt.Sprintf("/api/v1/auth/jwks/%s", tenantID)

	// Set up the mock expectation
	mockClient.On("CreateInvalidation", mock.Anything, mock.MatchedBy(func(input *cloudfront.CreateInvalidationInput) bool {
		return *input.DistributionId == distributionID && input.InvalidationBatch.Paths.Items[0] == path
	})).Return(&cloudfront.CreateInvalidationOutput{}, nil)

	// Call the method
	err := adapter.PurgeTenantJWKS(context.Background(), tenantID)

	// Assert the results
	assert.NoError(t, err)
	mockClient.AssertExpectations(t)
}

// TestAWSCloudFrontAdapter_PurgePath_Error tests error handling in PurgePath.
func TestAWSCloudFrontAdapter_PurgePath_Error(t *testing.T) {
	mockClient := new(MockCloudFrontClient)
	log := logger.NewNoopLogger()
	distributionID := "E123ABC456DEF"

	adapter := cdn.NewAWSCloudFrontAdapterWithClient(mockClient, distributionID, log)

	path := "/some/test/path"

	// Set up the mock expectation to return an error
	expectedError := fmt.Errorf("aws api error")
	mockClient.On("CreateInvalidation", mock.Anything, mock.Anything).Return(&cloudfront.CreateInvalidationOutput{}, expectedError)

	// Call the method
	err := adapter.PurgePath(context.Background(), path)

	// Assert the results
	assert.Error(t, err)
	assert.Contains(t, err.Error(), expectedError.Error())
	mockClient.AssertExpectations(t)
}
