package policy

import (
	"context"
	"fmt"
	"os"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"gopkg.in/yaml.v3"
)

// StaticPolicyEngine implements the PolicyEngine interface.
type StaticPolicyEngine struct {
	policies map[string]KeyPolicy
}

// KeyPolicy defines the policy for a compliance class.
type KeyPolicy struct {
	MinKeySize int `yaml:"minKeySize"`
}

// NewStaticPolicyEngine creates a new StaticPolicyEngine.
func NewStaticPolicyEngine(policyFilePath string) (service.PolicyEngine, error) {
	file, err := os.ReadFile(policyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policies map[string]KeyPolicy
	if err := yaml.Unmarshal(file, &policies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy file: %w", err)
	}

	return &StaticPolicyEngine{policies: policies}, nil
}

// CHeckKeyGeneration checks if the key generation request is compliant with the policy.
func (e *StaticPolicyEngine) CheckKeyGeneration(ctx context.Context, policyRequest models.PolicyRequest) error {
	policy, ok := e.policies[policyRequest.ComplianceClass]
	if !ok {
		return fmt.Errorf("policy not found for compliance class: %s", policyRequest.ComplianceClass)
	}

	if policyRequest.KeySize < policy.MinKeySize {
		return fmt.Errorf("key size %d is less than the minimum required size %d for compliance class %s",
			policyRequest.KeySize, policy.MinKeySize, policyRequest.ComplianceClass)
	}

	return nil
}
