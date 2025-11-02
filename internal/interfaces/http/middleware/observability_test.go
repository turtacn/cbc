//go:build test
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
)

func TestObservabilityMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tracer := otel.Tracer("test-tracer")

	router := gin.New()
	router.Use(ObservabilityMiddleware(tracer))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check metrics
	assert.Equal(t, 1, testutil.CollectAndCount(httpRequestsTotal))
	assert.Equal(t, 1, testutil.CollectAndCount(httpRequestDuration))
}
