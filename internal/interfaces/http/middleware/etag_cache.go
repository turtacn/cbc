package middleware

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// bodyCacheWriter is a custom ResponseWriter that captures the response body.
type bodyCacheWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyCacheWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

// ETagCache is a middleware that provides ETag-based caching for GET requests.
func ETagCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}

		// Replace the response writer with our custom writer to buffer the response
		blw := &bodyCacheWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		c.Next()

		// Get the response body from our buffer
		responseBody := blw.body.Bytes()
		statusCode := c.Writer.Status()

		// Only cache successful responses
		if statusCode == http.StatusOK && len(responseBody) > 0 {
			// Calculate the ETag from the response body
			hash := sha256.Sum256(responseBody)
			etag := fmt.Sprintf(`"%x"`, hash)

			// Check the If-None-Match header from the request
			if match := c.GetHeader("If-None-Match"); match == etag {
				c.Status(http.StatusNotModified)
				// Setting the body to nil is important to avoid sending the original body
				c.Writer.Write([]byte{})
				return
			}

			// Set the ETag and Cache-Control headers on the response
			c.Header("ETag", etag)
			c.Header("Cache-Control", "public, max-age=3600, must-revalidate")
		}

		// Write the original response body to the original writer
		blw.ResponseWriter.Write(responseBody)
	}
}
