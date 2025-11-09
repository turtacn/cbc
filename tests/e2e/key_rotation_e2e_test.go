//go:build integration
// +build integration

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/tests"
)

func TestKeyRotationE2EWithETag(t *testing.T) {
	ctx := context.Background()
	tenantID := "e2e-etag-rotate"

	// 1. Initial JWKS request
	resp1 := getJWKS(t, tenantID, "")
	assert.Equal(t, http.StatusOK, resp1.Code)
	etag1 := resp1.Header().Get("ETag")
	assert.NotEmpty(t, etag1)

	var jwks1 map[string]interface{}
	json.Unmarshal(resp1.Body.Bytes(), &jwks1)
	assert.Len(t, jwks1["keys"], 1)
	initialKID := jwks1["keys"].([]interface{})[0].(map[string]interface{})["kid"].(string)

	// 2. Second request with same ETag should be 304 Not Modified
	resp2 := getJWKS(t, tenantID, etag1)
	assert.Equal(t, http.StatusNotModified, resp2.Code)
	assert.Empty(t, resp2.Body.Bytes())

	// 3. Rotate key
	rotateKey(t, tenantID)

	// 4. Request after rotation with old ETag should be 200 OK
	resp3 := getJWKS(t, tenantID, etag1)
	assert.Equal(t, http.StatusOK, resp3.Code)
	etag2 := resp3.Header().Get("ETag")
	assert.NotEmpty(t, etag2)
	assert.NotEqual(t, etag1, etag2)

	var jwks2 map[string]interface{}
	json.Unmarshal(resp3.Body.Bytes(), &jwks2)
	assert.Len(t, jwks2["keys"], 2)

	// 5. Request with new ETag should be 304
	resp4 := getJWKS(t, tenantID, etag2)
	assert.Equal(t, http.StatusNotModified, resp4.Code)

	// 6. Compromise key
	compromiseKey(t, tenantID, initialKID)

	// 7. Request after compromise with old ETag should be 200 OK
	resp5 := getJWKS(t, tenantID, etag2)
	assert.Equal(t, http.StatusOK, resp5.Code)
	etag3 := resp5.Header().Get("ETag")
	assert.NotEmpty(t, etag3)
	assert.NotEqual(t, etag2, etag3)

	var jwks3 map[string]interface{}
	json.Unmarshal(resp5.Body.Bytes(), &jwks3)
	assert.Len(t, jwks3["keys"], 1)

	// 8. Final request with latest ETag should be 304
	resp6 := getJWKS(t, tenantID, etag3)
	assert.Equal(t, http.StatusNotModified, resp6.Code)
}

func getJWKS(t *testing.T, tenantID string, etag string) *httptest.ResponseRecorder {
	req, _ := http.NewRequest("GET", "/api/v1/auth/jwks/"+tenantID, nil)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	return tests.ExecuteRequest(req)
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
