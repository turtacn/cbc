package middleware

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

// bodyCacheWriter is a custom gin.ResponseWriter that intercepts and buffers the response body.
// This allows the ETag middleware to calculate a hash of the body before it's sent to the client.
// bodyCacheWriter 是一个自定义的 gin.ResponseWriter，用于拦截和缓冲响应正文。
// 这允许 ETag 中间件在将正文发送到客户端之前计算其哈希值。
type bodyCacheWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

// Write captures the data written to the response body instead of sending it immediately.
// Write 捕获写入响应正文的数据，而不是立即发送它。
func (w bodyCacheWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

// ETagCache returns a Gin middleware that implements ETag-based HTTP caching.
// It intercepts GET requests, calculates a SHA-256 hash of the response body to create an ETag,
// and checks the `If-None-Match` request header. If the ETags match, it returns a 304 Not Modified status.
// Otherwise, it adds the ETag and Cache-Control headers to the response.
// ETagCache 返回一个实现基于 ETag 的 HTTP 缓存的 Gin 中间件。
// 它拦截 GET 请求，计算响应正文的 SHA-256 哈希以创建 ETag，并检查 `If-None-Match` 请求标头。
// 如果 ETag 匹配，它将返回 304 Not Modified 状态。否则，它会将 ETag 和 Cache-Control 标头添加到响应中。
func ETagCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		// This middleware only applies to GET requests.
		if c.Request.Method != http.MethodGet {
			c.Next()
			return
		}

		// Replace the original response writer with our buffering writer.
		bcw := &bodyCacheWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = bcw

		// Process the request through the next handlers.
		c.Next()

		// After the handler has run, we can access the buffered body and status code.
		responseBody := bcw.body.Bytes()
		statusCode := c.Writer.Status()

		// Only apply ETag for successful responses with a body.
		if statusCode == http.StatusOK && len(responseBody) > 0 {
			// Calculate the ETag using a SHA-256 hash of the response body.
			hash := sha256.Sum256(responseBody)
			etag := fmt.Sprintf(`"%x"`, hash) // ETag format requires double quotes.

			// Check if the client's provided ETag matches the new one.
			if match := c.GetHeader("If-None-Match"); match == etag {
				// If they match, send a 304 Not Modified response without a body.
				c.Status(http.StatusNotModified)
				// It's crucial to explicitly write an empty body to the original writer.
				bcw.ResponseWriter.Write([]byte{})
				return
			}

			// If no match, set the ETag and Cache-Control headers for the client to use next time.
			c.Header("ETag", etag)
			c.Header("Cache-Control", "public, max-age=3600, must-revalidate")
		}

		// Finally, write the captured response body to the original response writer to send it to the client.
		bcw.ResponseWriter.Write(responseBody)
	}
}
