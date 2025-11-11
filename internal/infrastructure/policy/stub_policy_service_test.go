package policy

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/service"
)

// StubPolicyService provides a mock implementation of the service.PolicyService interface.
// It is used for testing and development purposes where a real policy engine is not required.
// StubPolicyService 提供了 service.PolicyService 接口的模拟实现。
// 它用于不需要真正策略引擎的测试和开发目的。
type StubPolicyService struct{}

// NewStubPolicyService creates a new instance of the StubPolicyService.
// NewStubPolicyService 创建一个新的 StubPolicyService 实例。
func NewStubPolicyService() *StubPolicyService {
	return &StubPolicyService{}
}

// EvaluateTrustLevel provides a stub implementation that returns a static trust level.
// It returns "medium" if a fingerprint is provided, otherwise "low".
// EvaluateTrustLevel 提供了一个返回静态信任级别的存根实现。
// 如果提供了指纹，则返回“medium”，否则返回“low”。
func (s *StubPolicyService) EvaluateTrustLevel(ctx context.Context, fingerprint string) (string, error) {
	if fingerprint != "" {
		return "medium", nil
	}
	return "low", nil
}

// EvaluateContextAccess provides a stub implementation that always grants access.
// It returns `true` regardless of the input claims or context.
// EvaluateContextAccess 提供了一个始终授予访问权限的存根实现。
// 无论输入声明或上下文如何，它都返回 `true`。
func (s *StubPolicyService) EvaluateContextAccess(ctx context.Context, claims jwt.MapClaims, e_context map[string]interface{}) (bool, error) {
	return true, nil
}

// इंश्योर कि StubPolicyService, service.PolicyService इंटरफ़ेस को लागू करता है।
var _ service.PolicyService = (*StubPolicyService)(nil)
