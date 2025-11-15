
// tests/e2e/security_regression_test.go
package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service/mocks"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func generateClientAssertion(t *testing.T, clientID, tenantID, jti string) string {
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": "https://localhost:8080",
		"jti": jti,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := token.SignedString([]byte("secret"))
	assert.NoError(t, err)
	return signedString
}

func Test_Security_Regression_TokenRotation_ReplayAttack(t *testing.T) {
	// Arrange
	authAppService := new(mocks.AuthAppService)
	deviceAuthAppService := new(mocks.MockDeviceAuthAppService) // Although not used here, the handler requires it.
	log := logger.NewDefaultLogger()
	authHandler := handlers.NewAuthHandler(authAppService, deviceAuthAppService, log)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/auth/token", authHandler.RefreshToken)

	initialRefreshToken := "token-A"
	tokenB := "token-B"
	tokenC := "token-C"
	initialTenantID := "tenant-1"

	// (a) Expect RefreshToken with Token A, return Token B
	authAppService.On("RefreshToken", mock.Anything, mock.MatchedBy(func(req *dto.RefreshTokenRequest) bool {
		return req.RefreshToken == initialRefreshToken
	})).Return(&dto.TokenResponse{
		AccessToken:  "access-token-X",
		RefreshToken: tokenB,
	}, nil).Once()

	// (b) Expect RefreshToken with Token A again, return invalid_grant
	authAppService.On("RefreshToken", mock.Anything, mock.MatchedBy(func(req *dto.RefreshTokenRequest) bool {
		return req.RefreshToken == initialRefreshToken
	})).Return(nil, errors.ErrInvalidGrant("token has been revoked")).Once()

	// (c) Expect RefreshToken with Token B, return Token C
	authAppService.On("RefreshToken", mock.Anything, mock.MatchedBy(func(req *dto.RefreshTokenRequest) bool {
		return req.RefreshToken == tokenB
	})).Return(&dto.TokenResponse{
		AccessToken:  "access-token-Y",
		RefreshToken: tokenC,
	}, nil).Once()

	// --- Act & Assert ---

	// (a) Use Refresh Token A to get Token B and Access Token X.
	body1 := strings.NewReader(`{"refresh_token":"` + initialRefreshToken + `","tenant_id":"` + initialTenantID + `"}`)
	req1, _ := http.NewRequest("POST", "/api/v1/auth/token", body1)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	var resp1 dto.TokenResponse
	err := json.Unmarshal(w1.Body.Bytes(), &resp1)
	assert.NoError(t, err)
	assert.Equal(t, tokenB, resp1.RefreshToken)

	// (b) Immediately use Token A again, assert server returns invalid_grant error.
	body2 := strings.NewReader(`{"refresh_token":"` + initialRefreshToken + `","tenant_id":"` + initialTenantID + `"}`)
	req2, _ := http.NewRequest("POST", "/api/v1/auth/token", body2)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusBadRequest, w2.Code)
	var errResp ErrorResponse
	err = json.Unmarshal(w2.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)

	// (c) Use Token B, assert can successfully get Token C and Access Token Y.
	body3 := strings.NewReader(`{"refresh_token":"` + tokenB + `","tenant_id":"` + initialTenantID + `"}`)
	req3, _ := http.NewRequest("POST", "/api/v1/auth/token", body3)
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	assert.Equal(t, http.StatusOK, w3.Code)
	var resp2 dto.TokenResponse
	err = json.Unmarshal(w3.Body.Bytes(), &resp2)
	assert.NoError(t, err)
	assert.Equal(t, tokenC, resp2.RefreshToken)

	authAppService.AssertExpectations(t)
}

func Test_Security_Regression_MGRAssertion(t *testing.T) {
	// Arrange
	authAppService := new(mocks.AuthAppService) // Although not used here, the handler requires it.
	deviceAuthAppService := new(mocks.MockDeviceAuthAppService)
	log := logger.NewDefaultLogger()
	authHandler := handlers.NewAuthHandler(authAppService, deviceAuthAppService, log)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/v1/auth/register-device", authHandler.RegisterDevice)

	jti := "unique-jti-123"
	clientAssertion := generateClientAssertion(t, "test-client", "tenant-1", jti)
	const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	const grantType = "client_credentials"

	// (a) Attempt with client_secret is handled by handler validation, no service call expected.

	// (b) Expect RegisterDevice with the assertion, return OK
	deviceAuthAppService.On("RegisterDevice", mock.Anything, mock.MatchedBy(func(req *dto.RegisterDeviceRequest) bool {
		return req.ClientAssertion == clientAssertion
	})).Return(&dto.TokenResponse{
		AccessToken:  "access-token-Z",
		RefreshToken: "refresh-token-Z",
	}, nil).Once()

	// (c) Expect RegisterDevice with the same assertion again, return invalid_grant (replay)
	deviceAuthAppService.On("RegisterDevice", mock.Anything, mock.MatchedBy(func(req *dto.RegisterDeviceRequest) bool {
		return req.ClientAssertion == clientAssertion
	})).Return(nil, errors.ErrInvalidGrant("JTI has been used")).Once()

	// --- Act & Assert ---

	// (a) Attempt to use client_secret, assert 400 error because client_assertion is missing
	body1 := strings.NewReader(`{"grant_type":"` + grantType + `", "client_id":"test-client","client_secret":"test-secret","tenant_id":"tenant-1","agent_id":"agent-1","device_fingerprint":"fingerprint-1"}`)
	req1, _ := http.NewRequest("POST", "/api/v1/auth/register-device", body1)
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusBadRequest, w1.Code)

	// (b) Use a valid, new client_assertion, assert 201 Created
	body2Str := `{"grant_type":"` + grantType + `", "client_assertion_type":"` + clientAssertionType + `", "client_id":"test-client","client_assertion":"` + clientAssertion + `","tenant_id":"tenant-1","agent_id":"agent-1","device_fingerprint":"fingerprint-1"}`
	req2, _ := http.NewRequest("POST", "/api/v1/auth/register-device", strings.NewReader(body2Str))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusCreated, w2.Code)
	var resp1 dto.TokenResponse
	err := json.Unmarshal(w2.Body.Bytes(), &resp1)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp1.AccessToken)

	// (c) Immediately reuse the same client_assertion, assert invalid_grant
	body3Str := `{"grant_type":"` + grantType + `", "client_assertion_type":"` + clientAssertionType + `", "client_id":"test-client","client_assertion":"` + clientAssertion + `","tenant_id":"tenant-1","agent_id":"agent-1","device_fingerprint":"fingerprint-1"}`
	req3, _ := http.NewRequest("POST", "/api/v1/auth/register-device", strings.NewReader(body3Str))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)

	assert.Equal(t, http.StatusBadRequest, w3.Code)
	var errResp ErrorResponse
	err = json.Unmarshal(w3.Body.Bytes(), &errResp)
	assert.NoError(t, err)
	assert.Equal(t, "invalid_grant", errResp.Error)

	deviceAuthAppService.AssertExpectations(t)
}
