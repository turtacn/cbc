//go:build integration

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/domain/models"
)

// MockCDNCacheManager is a mock implementation of the CDNCacheManager interface for E2E tests.
type MockCDNCacheManager struct {
	mock.Mock
	purgeCalled chan bool
}

func (m *MockCDNCacheManager) PurgeTenantJWKS(ctx context.Context, tenantID string) error {
	m.Called(ctx, tenantID)
	m.purgeCalled <- true
	return nil
}

func (m *MockCDNCacheManager) PurgePath(ctx context.Context, path string) error {
	m.Called(ctx, path)
	return nil
}

func TestCDN_Purge_On_Key_Compromise(t *testing.T) {
	// Setup: Initialize the test suite
	suite, err := NewE2ETestSuite()
	assert.NoError(t, err)
	defer suite.TearDown()

	// Create a new tenant for the test
	tenantID := "e2e-cdn-purge-test"
	err = suite.TenantRepo.Save(context.Background(), &models.Tenant{TenantID: tenantID})
	assert.NoError(t, err)

	// Rotate the key to get an active key
	kid, err := suite.KMS.RotateTenantKey(context.Background(), tenantID)
	assert.NoError(t, err)

	// Replace the CDN manager with a mock
	mockCDNManager := &MockCDNCacheManager{purgeCalled: make(chan bool, 1)}
	suite.App.SetCDNCacheManager(mockCDNManager)

	// Expect the PurgeTenantJWKS method to be called
	mockCDNManager.On("PurgeTenantJWKS", mock.Anything, tenantID).Return(nil)

	// Execute the key compromise
	err = suite.KMS.CompromiseKey(context.Background(), tenantID, kid, "e2e test")
	assert.NoError(t, err)

	// Verify that the PurgeTenantJWKS method was called
	select {
	case <-mockCDNManager.purgeCalled:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for CDN purge to be called")
	}

	mockCDNManager.AssertExpectations(t)
}
