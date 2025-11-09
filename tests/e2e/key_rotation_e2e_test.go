//go:build integration
// +build integration

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/config"
	"github.com/turtacn/cbc/internal/domain/repository"
	"github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/tests"
)

func TestKeyRotationE2E(t *testing.T) {
	// This test requires a running instance of the service and its dependencies.
	// For now, it serves as a placeholder for the E2E test.
	// t.Skip("Skipping test due to complex setup requirement")

	ctx := context.Background()
	tenantID := "e2e-rotate"

	// 1. Get initial JWKS
	jwks := getJWKS(t, tenantID)
	assert.Len(t, jwks["keys"], 1)
	initialKID := jwks["keys"].([]interface{})[0].(map[string]interface{})["kid"].(string)

	// 2. Rotate key
	rotateKey(t, tenantID)

	// 3. Get updated JWKS
	jwks = getJWKS(t, tenantID)
	assert.Len(t, jwks["keys"], 2)

	// 4. Compromise key
	compromiseKey(t, tenantID, initialKID)

	// 5. Get final JWKS
	jwks = getJWKS(t, tenantID)
	assert.Len(t, jwks["keys"], 1)
	finalKID := jwks["keys"].([]interface{})[0].(map[string]interface{})["kid"].(string)
	assert.NotEqual(t, initialKID, finalKID)
}

func getJWKS(t *testing.T, tenantID string) map[string]interface{} {
	req, _ := http.NewRequest("GET", "/api/v1/auth/jwks/"+tenantID, nil)
	resp := tests.ExecuteRequest(req)
	assert.Equal(t, http.StatusOK, resp.Code)

	var jwks map[string]interface{}
	json.Unmarshal(resp.Body.Bytes(), &jwks)
	return jwks
}

func rotateKey(t *testing.T, tenantID string) {
	cmd := exec.Command("go", "run", "../../cmd/cli/admin_key.go", "key", "rotate", "--tenant", tenantID)
	err := cmd.Run()
	assert.NoError(t, err)
}

func compromiseKey(t *testing.T, tenantID, kid string) {
	cmd := exec.Command("go", "run", "../../cmd/cli/admin_key.go", "key", "compromise", "--tenant", tenantID, "--kid", kid)
	err := cmd.Run()
	assert.NoError(t, err)
}
