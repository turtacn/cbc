package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/internal/interfaces/http/middleware"
)

func TestETagCache(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("first request should return 200 and set ETag", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.ETagCache())
		router.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "Hello, World!")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("ETag"))
		assert.Equal(t, "Hello, World!", w.Body.String())
	})

	t.Run("second request with matching ETag should return 304", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.ETagCache())
		router.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "Hello, World!")
		})

		// First request to get the ETag
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "/", nil)
		router.ServeHTTP(w1, req1)
		etag := w1.Header().Get("ETag")

		// Second request with the ETag
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/", nil)
		req2.Header.Set("If-None-Match", etag)
		router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusNotModified, w2.Code)
		assert.Empty(t, w2.Body.String())
	})

	t.Run("request with mismatched ETag should return 200", func(t *testing.T) {
		router := gin.New()
		router.Use(middleware.ETagCache())
		router.GET("/", func(c *gin.Context) {
			c.String(http.StatusOK, "Hello, World!")
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/", nil)
		req.Header.Set("If-None-Match", `"wrong-etag"`)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotEmpty(t, w.Header().Get("ETag"))
		assert.Equal(t, "Hello, World!", w.Body.String())
	})
}
