// internal/interfaces/http/handlers/auth_handler_test.go
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/pkg/errors"
)

type MockAuthAppService struct {
	mock.Mock
}

func (m *MockAuthAppService) IssueToken(ctx context.Context, req *dto.IssueTokenRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

func (m *MockAuthAppService) RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

func (m *MockAuthAppService) RevokeToken(ctx context.Context, req *dto.RevokeTokenRequest) error {
	args := m.Called(ctx, req)
	return args.Error(0)
}

func (m *MockAuthAppService) ValidateToken(ctx context.Context, req *dto.ValidateTokenRequest) (*dto.TokenValidationResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenValidationResponse), args.Error(1)
}

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestAuthHandler_IssueToken(t *testing.T) {
	mockService := new(MockAuthAppService)
	handler := NewAuthHandler(mockService)
	router := setupTestRouter()
	router.POST("/api/v1/auth/token", handler.IssueToken)

	tenantID := uuid.New()

	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func()
		expectedStatus int
		checkResponse  func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "Successfully issue token",
			requestBody: map[string]interface{}{
				"tenant_id":   tenantID.String(),
				"device_id":   "test-device-001",
				"device_type": "mobile",
				"fingerprint": "test-fingerprint",
				"scope":       "agent:read agent:write",
			},
			setupMock: func() {
				expectedReq := &dto.IssueTokenRequest{
					TenantID:    tenantID,
					DeviceID:    "test-device-001",
					DeviceType:  "mobile",
					Fingerprint: "test-fingerprint",
					Scope:       "agent:read agent:write",
				}
				response := &dto.TokenResponse{
					AccessToken:  "jwt.access.token",
					RefreshToken: "jwt.refresh.token",
					TokenType:    "Bearer",
					ExpiresIn:    900,
				}
				mockService.On("IssueToken", mock.Anything, mock.MatchedBy(func(req *dto.IssueTokenRequest) bool {
					return req.TenantID == expectedReq.TenantID &&
						req.DeviceID == expectedReq.DeviceID &&
						req.DeviceType == expectedReq.DeviceType
				})).Return(response, nil).Once()
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				var response dto.TokenResponse
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, "jwt.access.token", response.AccessToken)
				assert.Equal(t, "jwt.refresh.token", response.RefreshToken)
				assert.Equal(t, "Bearer", response.TokenType)
				assert.Equal(t, int64(900), response.ExpiresIn)
			},
		},
		{
			name: "Invalid request body",
			requestBody: map[string]interface{}{
				"tenant_id": "invalid-uuid",
			},
			setupMock:      func() {},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "error")
			},
		},
		{
			name: "Tenant not found",
			requestBody: map[string]interface{}{
				"tenant_id":   tenantID.String(),
				"device_id":   "test-device-001",
				"device_type": "mobile",
				"fingerprint": "test-fingerprint",
				"scope":       "agent:read",
			},
			setupMock: func() {
				mockService.On("IssueToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrTenantNotFound).Once()
			},
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "not found")
			},
		},
		{
			name: "Rate limit exceeded",
			requestBody: map[string]interface{}{
				"tenant_id":   tenantID.String(),
				"device_id":   "test-device-001",
				"device_type": "mobile",
				"fingerprint": "test-fingerprint",
				"scope":       "agent:read",
			},
			setupMock: func() {
				mockService.On("IssueToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrRateLimitExceeded).Once()
			},
			expectedStatus: http.StatusTooManyRequests,
			checkResponse: func(t *testing.T, w *httptest.ResponseRecorder) {
				assert.Contains(t, w.Body.String(), "rate limit")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			tt.checkResponse(t, w)

			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_RefreshToken(t *testing.T) {
	mockService := new(MockAuthAppService)
	handler := NewAuthHandler(mockService)
	router := setupTestRouter()
	router.POST("/api/v1/auth/refresh", handler.RefreshToken)

	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func()
		expectedStatus int
	}{
		{
			name: "Successfully refresh token",
			requestBody: map[string]interface{}{
				"refresh_token": "valid.refresh.token",
			},
			setupMock: func() {
				response := &dto.TokenResponse{
					AccessToken:  "new.access.token",
					RefreshToken: "new.refresh.token",
					TokenType:    "Bearer",
					ExpiresIn:    900,
				}
				mockService.On("RefreshToken", mock.Anything, mock.Anything).
					Return(response, nil).Once()
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid refresh token",
			requestBody: map[string]interface{}{
				"refresh_token": "invalid.token",
			},
			setupMock: func() {
				mockService.On("RefreshToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrInvalidToken).Once()
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthHandler_ValidateToken(t *testing.T) {
	mockService := new(MockAuthAppService)
	handler := NewAuthHandler(mockService)
	router := setupTestRouter()
	router.POST("/api/v1/auth/validate", handler.ValidateToken)

	tests := []struct {
		name           string
		requestBody    interface{}
		setupMock      func()
		expectedStatus int
	}{
		{
			name: "Valid token",
			requestBody: map[string]interface{}{
				"token": "valid.access.token",
			},
			setupMock: func() {
				response := &dto.TokenValidationResponse{
					Valid:     true,
					TenantID:  uuid.New(),
					DeviceID:  uuid.New(),
					TokenType: "access",
					Scope:     "agent:read agent:write",
					ExpiresAt: time.Now().Add(15 * time.Minute),
				}
				mockService.On("ValidateToken", mock.Anything, mock.Anything).
					Return(response, nil).Once()
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid token",
			requestBody: map[string]interface{}{
				"token": "invalid.token",
			},
			setupMock: func() {
				mockService.On("ValidateToken", mock.Anything, mock.Anything).
					Return(nil, errors.ErrInvalidToken).Once()
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/validate", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockService.AssertExpectations(t)
		})
	}
}
