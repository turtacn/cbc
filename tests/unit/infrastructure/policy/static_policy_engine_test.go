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
`)
	assert.NoError(t, err)
	policyFile.Close()

	// Test NewStaticPolicyEngine
	engine, err := policy.NewStaticPolicyEngine(policyFile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, engine)

	// Test CHeckKeyGeneration
	err = engine.CheckKeyGeneration(context.Background(), models.PolicyRequest{ComplianceClass: "L1", KeySize: 2048})
	assert.NoError(t, err)

	err = engine.CheckKeyGeneration(context.Background(), models.PolicyRequest{ComplianceClass: "L1", KeySize: 1024})
	assert.Error(t, err)

	err = engine.CheckKeyGeneration(context.Background(), models.PolicyRequest{ComplianceClass: "L3", KeySize: 4096})
	assert.NoError(t, err)

	err = engine.CheckKeyGeneration(context.Background(), models.PolicyRequest{ComplianceClass: "L3", KeySize: 2048})
	assert.Error(t, err)

	err = engine.CheckKeyGeneration(context.Background(), models.PolicyRequest{ComplianceClass: "L2", KeySize: 2048})
	assert.Error(t, err)
}
