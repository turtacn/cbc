package policy_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/infrastructure/policy"
)

func TestStaticPolicyEngine(t *testing.T) {
	// Create a temporary policy file
	policyFile, err := os.CreateTemp("", "policies.yaml")
	assert.NoError(t, err)
	defer os.Remove(policyFile.Name())

	_, err = policyFile.WriteString(`
L1:
  minKeySize: 2048
L3:
  minKeySize: 4096
  blockOnAnomalyScore: 0.9
`)
	assert.NoError(t, err)
	policyFile.Close()

	engine, err := policy.NewStaticPolicyEngine(policyFile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, engine)

	testCases := []struct {
		name        string
		request     models.PolicyRequest
		expectError bool
	}{
		{
			name:        "L1_ValidKeySize_NoRisk",
			request:     models.PolicyRequest{ComplianceClass: "L1", KeySize: 2048},
			expectError: false,
		},
		{
			name:        "L1_InvalidKeySize_NoRisk",
			request:     models.PolicyRequest{ComplianceClass: "L1", KeySize: 1024},
			expectError: true,
		},
		{
			name:        "L3_ValidKeySize_NoRisk",
			request:     models.PolicyRequest{ComplianceClass: "L3", KeySize: 4096},
			expectError: false,
		},
		{
			name:        "L3_InvalidKeySize_NoRisk",
			request:     models.PolicyRequest{ComplianceClass: "L3", KeySize: 2048},
			expectError: true,
		},
		{
			name:        "L2_UnknownClass",
			request:     models.PolicyRequest{ComplianceClass: "L2", KeySize: 2048},
			expectError: true,
		},
		{
			name: "L3_ValidKeySize_LowRisk",
			request: models.PolicyRequest{
				ComplianceClass: "L3",
				KeySize:         4096,
				CurrentRiskProfile: &models.TenantRiskProfile{
					AnomalyScore: 0.5,
				},
			},
			expectError: false,
		},
		{
			name: "L3_ValidKeySize_HighRisk",
			request: models.PolicyRequest{
				ComplianceClass: "L3",
				KeySize:         4096,
				CurrentRiskProfile: &models.TenantRiskProfile{
					AnomalyScore: 0.95,
				},
			},
			expectError: true,
		},
		{
			name: "L1_ValidKeySize_HighRisk_NoBlock",
			request: models.PolicyRequest{
				ComplianceClass: "L1",
				KeySize:         2048,
				CurrentRiskProfile: &models.TenantRiskProfile{
					AnomalyScore: 0.95,
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := engine.CheckKeyGeneration(context.Background(), tc.request)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
