package policy

import (
	"context"
	"fmt"
	"os"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	"gopkg.in/yaml.v3"
)

// StaticPolicyEngine implements the service.PolicyEngine interface using a static, file-based configuration.
// It loads policies from a YAML file at startup and uses them to validate requests.
// StaticPolicyEngine 使用静态的、基于文件的配置来实现 service.PolicyEngine 接口。
// 它在启动时从 YAML 文件加载策略，并使用它们来验证请求。
type StaticPolicyEngine struct {
	policies map[string]KeyPolicy
}

// KeyPolicy defines the specific policy rules for a given compliance class.
// These rules are loaded from the YAML configuration file.
// KeyPolicy 定义了给定合规性类别的具体策略规则。
// 这些规则是从 YAML 配置文件中加载的。
type KeyPolicy struct {
	// MinKeySize is the minimum required bit size for cryptographic keys in this class.
	// MinKeySize 是此类中加密密钥所需的最小位数。
	MinKeySize int `yaml:"minKeySize"`
	// BlockOnAnomalyScore is a risk threshold. If a tenant's anomaly score meets or exceeds this value,
	// certain operations (like key generation) will be blocked. A value of 0 disables this check.
	// BlockOnAnomalyScore 是一个风险阈值。如果租户的异常分数达到或超过此值，
	// 某些操作（如密钥生成）将被阻止。值为 0 表示禁用此检查。
	BlockOnAnomalyScore float64 `yaml:"blockOnAnomalyScore"`
}

// NewStaticPolicyEngine creates and initializes a new StaticPolicyEngine by loading policies from a specified file path.
// It returns an error if the policy file cannot be read or parsed.
// NewStaticPolicyEngine 通过从指定的文​​件路径加载策略来创建和初始化一个新的 StaticPolicyEngine。
// 如果无法读取或解析策略文件，它将返回错误。
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

// CheckKeyGeneration validates a key generation request against the loaded policies.
// It checks for compliance based on key size and the tenant's current risk profile.
// It returns an error if any policy rule is violated.
// CheckKeyGeneration 根据加载的策略验证密钥生成请求。
// 它根据密钥大小和租户当前的风险状况检查合规性。
// 如果违反任何策略规则，它将返回错误。
func (e *StaticPolicyEngine) CheckKeyGeneration(ctx context.Context, policyRequest models.PolicyRequest) error {
	policy, ok := e.policies[policyRequest.ComplianceClass]
	if !ok {
		return fmt.Errorf("policy not found for compliance class: %s", policyRequest.ComplianceClass)
	}

	// Check if the requested key size meets the minimum requirement for the compliance class.
	if policyRequest.KeySize < policy.MinKeySize {
		return fmt.Errorf("key size %d is less than the minimum required size %d for compliance class %s",
			policyRequest.KeySize, policy.MinKeySize, policyRequest.ComplianceClass)
	}

	// Check if the tenant's risk score exceeds the policy's blocking threshold.
	// This provides a dynamic, risk-based control over sensitive operations.
	if policyRequest.CurrentRiskProfile != nil &&
		policy.BlockOnAnomalyScore > 0 && // Ensure the policy has a threshold set
		policyRequest.CurrentRiskProfile.AnomalyScore >= policy.BlockOnAnomalyScore {
		return fmt.Errorf("policy violation: high anomaly score (%f) detected, exceeding threshold of %f",
			policyRequest.CurrentRiskProfile.AnomalyScore, policy.BlockOnAnomalyScore)
	}

	return nil
}

// EvaluateTrustLevel evaluates the trust level based on the risk profile.
// This is a placeholder implementation.
func (e *StaticPolicyEngine) EvaluateTrustLevel(ctx context.Context, riskProfile *models.TenantRiskProfile) models.TrustLevel {
	if riskProfile.AnomalyScore > 0.75 {
		return models.TrustLevelLow
	}
	if riskProfile.AnomalyScore > 0.5 {
		return models.TrustLevelMedium
	}
	return models.TrustLevelHigh
}
