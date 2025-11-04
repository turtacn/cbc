package policy

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/service"
)

type StubPolicyService struct{}

func NewStubPolicyService() *StubPolicyService {
	return &StubPolicyService{}
}

func (s *StubPolicyService) EvaluateTrustLevel(ctx context.Context, fingerprint string) (string, error) {
	if fingerprint != "" {
		return "medium", nil
	}
	return "low", nil
}

func (s *StubPolicyService) EvaluateContextAccess(ctx context.Context, claims jwt.MapClaims, e_context map[string]interface{}) (bool, error) {
	return true, nil
}

var _ service.PolicyService = (*StubPolicyService)(nil)
