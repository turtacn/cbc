package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStubPolicyService_EvaluateTrustLevel(t *testing.T) {
	service := NewStubPolicyService()

	t.Run("with fingerprint", func(t *testing.T) {
		level, err := service.EvaluateTrustLevel(context.Background(), "some-fingerprint")
		assert.NoError(t, err)
		assert.Equal(t, "medium", level)
	})

	t.Run("without fingerprint", func(t *testing.T) {
		level, err := service.EvaluateTrustLevel(context.Background(), "")
		assert.NoError(t, err)
		assert.Equal(t, "low", level)
	})
}

func TestStubPolicyService_EvaluateContextAccess(t *testing.T) {
	service := NewStubPolicyService()
	access, err := service.EvaluateContextAccess(context.Background(), nil, nil)
	assert.NoError(t, err)
	assert.True(t, access)
}
