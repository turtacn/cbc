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
	"github.com/turtacn/cbc/pkg/logger"
)

// MockAuthAppService is a mock for the AuthAppService
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

func (m *MockAuthAppService) IntrospectToken(ctx context.Context, token string) (*dto.TokenIntrospectionResponse, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenIntrospectionResponse), args.Error(1)
}

func (m *MockAuthAppService) RegisterDevice(ctx context.Context, req *dto.RegisterDeviceRequest) (*dto.TokenResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.TokenResponse), args.Error(1)
}

// MockHTTPMetrics is a mock for HTTPMetrics
type MockHTTPMetrics struct {
	mock.Mock
}

func (m *MockHTTPMetrics) RecordRequestStart(ctx context.Context, handler string) {
	m.Called(ctx, handler)
}

func (m *MockHTTPMetrics) RecordRequestError(ctx context.Context, handler string, httpStatus int) {
	m.Called(ctx, handler, httpStatus)
}

func (m *MockHTTPMetrics) RecordRequestSuccess(ctx context.Context, handler string) {
	m.Called(ctx, handler)
}

func (m *MockHTTPMetrics) RecordRequestDuration(ctx context.Context, handler string, status int, duration time.Duration) {
	m.Called(ctx, handler, status, duration)
}

func TestAuthHandler_IssueToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockAppService := new(MockAuthAppService)
	mockMetrics := new(MockHTTPMetrics)
	log := logger.NewDefaultLogger()

	handler := NewAuthHandler(mockAppService, mockMetrics, log)

	router := gin.Default()
	router.POST("/token", handler.IssueToken)

	tenantID := uuid.New().String()
	agentID := uuid.New().String()

	t.Run("Successfully issue token", func(t *testing.T) {
		reqBody := &dto.TokenIssueRequest{
			TenantID:  tenantID,
			AgentID:   agentID,
			GrantType: "device_credential",
		}
		jsonBody, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest(http.MethodPost, "/token", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		mockResponse := &dto.TokenResponse{
			AccessToken: "test-token",
		}

		mockMetrics.On("RecordRequestStart", mock.Anything, "issue_token").Return()
		mockAppService.On("IssueToken", mock.Anything, mock.MatchedBy(func(r *dto.IssueTokenRequest) bool {
			return r.TenantID == tenantID && r.AgentID == agentID
		})).Return(mockResponse, nil).Once()

		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)

		var respBody dto.TokenResponse
		err := json.Unmarshal(rr.Body.Bytes(), &respBody)
		assert.NoError(t, err)
		assert.Equal(t, mockResponse.AccessToken, respBody.AccessToken)

		mockAppService.AssertExpectations(t)
		mockMetrics.AssertExpectations(t)
	})
}
