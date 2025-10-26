package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/turtacn/cbc/internal/serverlite"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func TestAuthLifecycle_E2E(t *testing.T) {
	// Arrange
	signingKey := []byte("your-super-secret-hmac-key-for-e2e-testing")
	server := serverlite.NewServer(":8081", signingKey)
	testServer := httptest.NewServer(server.HttpServer.Handler)
	defer testServer.Close()

	client := testServer.Client()

	// 1. Issue Token (Happy Path)
	issueBody := map[string]string{
		"tenant_id": "tenant-123",
		"device_id": "device-abc",
	}
	bodyBytes, _ := json.Marshal(issueBody)
	issueReq, _ := http.NewRequest("POST", testServer.URL+"/token/issue", bytes.NewBuffer(bodyBytes))
	issueReq.Header.Set("Content-Type", "application/json")

	issueResp, err := client.Do(issueReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, issueResp.StatusCode)

	var tokenResp TokenResponse
	err = json.NewDecoder(issueResp.Body).Decode(&tokenResp)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.NotEmpty(t, tokenResp.RefreshToken)
	issueResp.Body.Close()

	// 2. Access with Token (Happy Path)
	// In a real scenario, you'd have a protected endpoint.
	// We'll simulate by verifying the token directly using the server's logic.
	_, err = server.VerifyAndParseToken(tokenResp.AccessToken, "access")
	assert.NoError(t, err, "Access token should be valid")

	// 3. Refresh Token (Happy Path)
	refreshBody := map[string]string{"refresh_token": tokenResp.RefreshToken}
	bodyBytes, _ = json.Marshal(refreshBody)
	refreshReq, _ := http.NewRequest("POST", testServer.URL+"/token/refresh", bytes.NewBuffer(bodyBytes))
	refreshReq.Header.Set("Content-Type", "application/json")

	refreshResp, err := client.Do(refreshReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, refreshResp.StatusCode)

	var refreshedTokenResp TokenResponse
	err = json.NewDecoder(refreshResp.Body).Decode(&refreshedTokenResp)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshedTokenResp.AccessToken)
	assert.NotEqual(t, tokenResp.AccessToken, refreshedTokenResp.AccessToken)
	refreshResp.Body.Close()

	// 4. Old Refresh Token should be invalid
	_, err = server.VerifyAndParseToken(tokenResp.RefreshToken, "refresh")
	assert.Error(t, err, "Old refresh token should be revoked after use")

	// 5. Revoke Token
	revokeBody := map[string]string{"token": refreshedTokenResp.AccessToken}
	bodyBytes, _ = json.Marshal(revokeBody)
	revokeReq, _ := http.NewRequest("POST", testServer.URL+"/token/revoke", bytes.NewBuffer(bodyBytes))
	revokeReq.Header.Set("Content-Type", "application/json")

	revokeResp, err := client.Do(revokeReq)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode)
	revokeResp.Body.Close()

	// 6. Revoked token should be invalid
	_, err = server.VerifyAndParseToken(refreshedTokenResp.AccessToken, "access")
	assert.Error(t, err, "Revoked access token should be invalid")
}
