package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/turtacn/cbc/internal/application/dto"
	"github.com/turtacn/cbc/internal/application/service"
	"github.com/turtacn/cbc/internal/interfaces/http/handlers"
	"github.com/turtacn/cbc/pkg/errors"
)

// MockAuthAppService is a mock of AuthAppService
type MockAuthAppService struct {
	mock.Mock
}

func (m *MockAuthAppService) IssueToken(ctx context.Context, req *dto.TokenIssueRequest) (*dto.TokenPairResponse, *errors.AppError) {
	args := m.Called(ctx, req)
	return args.Get(0).(*dto.TokenPairResponse), args.Get(1).(*errors.AppError)
}
// ... other methods mocked

func TestAuthHandler_IssueToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAppSvc := new(MockAuthAppService)
	authHandler := handlers.NewAuthHandler(mockAppSvc, nil) // Real implementation needs metrics

	router := gin.Default()
	router.POST("/auth/token", authHandler.IssueToken)

	// Test case 1: Success
	reqBody := dto.TokenIssueRequest{
		GrantType: "client_credentials",
		TenantID:  uuid.New(),
		DeviceID:  "test-device",
	}
	mockResp := &dto.TokenPairResponse{AccessToken: "abc", RefreshToken: "def"}
	mockAppSvc.On("IssueToken", mock.Anything, &reqBody).Return(mockResp, nil)

	bodyBytes, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/auth/token", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// ... assert response body

	// Test case 2: Validation error
	invalidReqBody := dto.TokenIssueRequest{}
	bodyBytes, _ = json.Marshal(invalidReqBody)
	req, _ = http.NewRequest(http.MethodPost, "/auth/token", bytes.NewBuffer(bodyBytes))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
//Personal.AI order the ending