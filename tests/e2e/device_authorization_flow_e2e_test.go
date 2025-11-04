//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/config"
	domain_service "github.com/turtacn/cbc/internal/domain/service"
	redisinfra "github.com/turtacn/cbc/internal/infrastructure/redis"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	httpRouter "github.com/turtacn/cbc/internal/interfaces/http/router"
	"github.com/turtacn/cbc/pkg/logger"
	"github.com/turtacn/cbc/tests/mocks"
)

func Test_Device_Authorization_Flow_E2E(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.NewNoopLogger()
	cfg := &config.Config{}
	cfg.OAuth.DevVerifyAPIEnabled = true

	// For this E2E test, we will use the real services
	// and a real in-memory redis
	// but we'll still mock the external dependencies like the db
	// and the crypto service for simplicity

	// For this E2E test, we will use the real services
	// and a real in-memory redis
	// but we'll still mock the external dependencies like the db
	// and the crypto service for simplicity
	redisServer, err := miniredis.Run()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub redis connection", err)
	}
	defer redisServer.Close()
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisServer.Addr(),
	})

	deviceAuthStore := redisinfra.NewRedisDeviceAuthStore(redisClient)
	tokenService := domain_service.NewTokenDomainService(nil, nil, log)
	mockCrypto := new(mocks.MockCryptoService)
	deviceAuthAppService := service.NewDeviceAuthAppService(deviceAuthStore, tokenService, mockCrypto, &cfg.OAuth)
	authAppService := service.NewAuthAppService(tokenService, nil, nil, nil, nil, nil, log)


	// Mocks
	mockDeviceApp := new(mocks.MockDeviceAppService)
	metrics := new(mocks.MockHTTPMetrics)
	metrics.On("RecordRequestStart", mock.Anything, mock.Anything).Return()
	metrics.On("RecordRequestDuration", mock.Anything, mock.Anything, mock.Anything, mock.AnythingOfType("time.Duration")).Return()
	metrics.On("RecordRequestError", mock.Anything, mock.Anything, mock.Anything).Return()

	// Setup handlers
	authHandler := handlers.NewAuthHandler(authAppService, deviceAuthAppService, metrics, log)
	deviceHandler := handlers.NewDeviceHandler(mockDeviceApp, metrics, log)
	jwksHandler := handlers.NewJWKSHandler(mockCrypto, log, nil)
	healthHandler := handlers.NewHealthHandler(nil, nil, log)
	oauthHandler := handlers.NewOAuthHandler(deviceAuthAppService)

	// Setup router
	router := httpRouter.NewRouter(cfg, log, healthHandler, authHandler, deviceHandler, jwksHandler, oauthHandler, nil, nil, nil, nil)
	router.SetupRoutes()
	engine := router.Engine()

	var deviceCode string
	var userCode string

	t.Run("Step 1: Start Device Authorization", func(t *testing.T) {
		reqBody := `client_id=test-client`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/device_authorization", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp handlers.DeviceAuthorizationResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp.DeviceCode)
		assert.NotEmpty(t, resp.UserCode)
		deviceCode = resp.DeviceCode
		userCode = resp.UserCode
	})

	t.Run("Step 2: Poll for Token (Pending)", func(t *testing.T) {
		reqBody := `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=` + deviceCode + `&client_id=test-client`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "authorization_pending", resp["error"])
	})

	t.Run("Step 3: Poll for Token (Slow Down)", func(t *testing.T) {
		time.Sleep(1 * time.Second)
		reqBody := `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=` + deviceCode + `&client_id=test-client`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "slow_down", resp["error"])
	})

	t.Run("Step 4: Approve User Code", func(t *testing.T) {
		reqBody := `{"user_code":"` + userCode + `","action":"approve","tenant_id":"t-1","subject":"user-1"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/verify", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("Step 5: Poll for Token (Approved)", func(t *testing.T) {
		time.Sleep(6 * time.Second)
		reqBody := `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=` + deviceCode + `&client_id=test-client`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.NotEmpty(t, resp["access_token"])
	})

	t.Run("Step 6: Poll for Token (Expired)", func(t *testing.T) {
		reqBody := `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=` + deviceCode + `&client_id=test-client`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewBufferString(reqBody))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp map[string]string
		json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Equal(t, "expired_token", resp["error"])
	})
}
