//go:build unit
// +build unit

package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/tests/mocks"
)

func TestOAuthHandler_StartDeviceAuthorization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAppService := new(mocks.AuthAppService)
	handler := handlers.NewOAuthHandler(mockAppService)

	// Setup mock response
	expectedResp := &application.DeviceFlowResponse{
		DeviceCode:      "test_dc",
		UserCode:        "test_uc",
		VerificationURI: "https://example.com/verify",
		ExpiresIn:       600,
		Interval:        5,
	}
	mockAppService.On("StartDeviceFlow", mock.Anything, "test_client", "read").Return(expectedResp, nil)

	// Create request
	router := gin.Default()
	router.POST("/device_authorization", handler.StartDeviceAuthorization)

	reqBody := "client_id=test_client&scope=read"
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Assertions
	assert.Equal(t, http.StatusOK, rr.Code)

	var actualResp handlers.DeviceAuthorizationResponse
	err := json.Unmarshal(rr.Body.Bytes(), &actualResp)
	assert.NoError(t, err)
	assert.Equal(t, expectedResp.DeviceCode, actualResp.DeviceCode)
	assert.Equal(t, expectedResp.UserCode, actualResp.UserCode)

	mockAppService.AssertExpectations(t)
}

func TestOAuthHandler_VerifyUserCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAppService := new(mocks.AuthAppService)
	handler := handlers.NewOAuthHandler(mockAppService)

	router := gin.Default()
	router.POST("/verify", handler.VerifyUserCode)

	// --- Test Case: Approve ---
	mockAppService.On("VerifyDeviceFlow", mock.Anything, "approve_uc", "approve", "tenant1", "user1").Return(nil).Once()

	approveBody := `{"user_code": "approve_uc", "action": "approve", "tenant_id": "tenant1", "subject": "user1"}`
	req := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewBufferString(approveBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)


	// --- Test Case: Deny ---
	mockAppService.On("VerifyDeviceFlow", mock.Anything, "deny_uc", "deny", "", "").Return(nil).Once()

	denyBody := `{"user_code": "deny_uc", "action": "deny"}`
	req = httptest.NewRequest(http.MethodPost, "/verify", bytes.NewBufferString(denyBody))
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)


	mockAppService.AssertExpectations(t)
}
