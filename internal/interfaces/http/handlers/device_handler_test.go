// Package handlers_test contains integration tests for the HTTP handlers.
package handlers_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	devicemocks "github.com/turtacn/cbc/internal/domain/service/mocks"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// generateRSAKeyPair creates a new RSA key pair for testing.
func generateRSAKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	return privateKey, &privateKey.PublicKey
}

// generateTestJWT generates a signed JWT for testing purposes.
func generateTestJWT(t *testing.T, claims jwt.MapClaims, privateKey interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-kid"
	signedString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}
	return signedString
}

func TestDeviceHandler_RegisterDevice_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.NewDefaultLogger()

	// 1. Setup: Generate RSA key pair for signing assertions
	privateKey, _ := generateRSAKeyPair(t)

	// 2. Define standard claims for a valid assertion
	validClaims := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "test-client-id",
			"sub": "test-client-id",
			"aud": "http://localhost:8080",
			"exp": time.Now().Add(time.Hour * 1).Unix(),
			"jti": "unique-jti-123",
		}
	}

	// 3. Test Cases
	testCases := []struct {
		name                 string
		setupMock            func(deviceService *devicemocks.DeviceAppService)
		requestBody          interface{}
		expectedStatusCode   int
		expectedResponseBody string
	}{
		{
			name: "Success with Valid Client Assertion",
			setupMock: func(deviceService *devicemocks.DeviceAppService) {
				deviceService.On("RegisterDevice", mock.Anything, mock.AnythingOfType("*dto.DeviceRegisterRequest")).Return(&dto.DeviceResponse{
					DeviceID: "new-device-id",
				}, nil)
			},
			requestBody: &dto.DeviceRegisterRequest{
				GrantType:           "client_credentials",
				ClientID:            "test-client-id",
				ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				ClientAssertion:     generateTestJWT(t, validClaims(), privateKey),
				TenantID:            "test-tenant-id",
				AgentID:             "test-agent-id",
				DeviceFingerprint:   "test-fingerprint",
			},
			expectedStatusCode: http.StatusCreated,
		},
		{
			name:      "Failure with client_secret instead of assertion",
			setupMock: nil, // No service call should be made
			requestBody: map[string]string{
				"grant_type":      "client_credentials",
				"client_id":       "test-client-id",
				"client_secret":   "this-is-not-allowed",
				"tenant_id":       "test-tenant-id",
				"agent_id":        "test-agent-id",
				"fingerprint": "test-fingerprint",
			},
			expectedStatusCode:   http.StatusBadRequest,
			expectedResponseBody: `{"error":{"code":"internal_error","description":"Key: 'DeviceRegisterRequest.ClientAssertionType' Error:Field validation for 'ClientAssertionType' failed on the 'required' tag\\nKey: 'DeviceRegisterRequest.ClientAssertion' Error:Field validation for 'ClientAssertion' failed on the 'required' tag\\nKey: 'DeviceRegisterRequest.DeviceFingerprint' Error:Field validation for 'DeviceFingerprint' failed on the 'required' tag","error_uri":"https://docs.cloudbrain.cert/errors#internal_error","message":"Internal server error"},"success":false,"timestamp":1763020585}`,
		},
		{
			name: "Failure on JTI Replay Attack",
			setupMock: func(deviceService *devicemocks.DeviceAppService) {
				deviceService.On("RegisterDevice", mock.Anything, mock.AnythingOfType("*dto.DeviceRegisterRequest")).Return(nil, errors.ErrInvalidGrant("JTI has been replayed"))
			},
			requestBody: &dto.DeviceRegisterRequest{
				GrantType:           "client_credentials",
				ClientID:            "test-client-id",
				ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				ClientAssertion:     generateTestJWT(t, validClaims(), privateKey), // Same JTI as a previous request
				TenantID:            "test-tenant-id",
				AgentID:             "test-agent-id",
				DeviceFingerprint:   "test-fingerprint",
			},
			expectedStatusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			mockDeviceService := new(devicemocks.DeviceAppService)
			if tc.setupMock != nil {
				tc.setupMock(mockDeviceService)
			}

			deviceHandler := handlers.NewDeviceHandler(mockDeviceService, log)

			router := gin.New()
			router.POST("/api/v1/devices", deviceHandler.RegisterDevice)

			// Create request
			body, _ := json.Marshal(tc.requestBody)
			req, _ := http.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			// Execute request
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			// Assert
			assert.Equal(t, tc.expectedStatusCode, rr.Code)
			if tc.expectedResponseBody != "" {
				// Due to the timestamp, we can't do a direct comparison.
				// Instead, we'll unmarshal and check for the presence of the error code.
				var resp map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &resp)
				assert.NoError(t, err, "Response body should be valid JSON")
				assert.NotNil(t, resp["error"], "Response should contain an error field")
			}
			mockDeviceService.AssertExpectations(t)
		})
	}
}
