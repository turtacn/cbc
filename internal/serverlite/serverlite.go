package serverlite

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Server is a lightweight, in-memory auth server for E2E testing.
type Server struct {
	HttpServer *http.Server
	revoked    sync.Map
	signingKey []byte
}

// NewServer creates and configures a new server.
func NewServer(addr string, signingKey []byte) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	s := &Server{
		signingKey: signingKey,
	}

	router.GET("/health", s.healthCheck)
	router.POST("/token/issue", s.issueToken)
	router.POST("/token/refresh", s.refreshToken)
	router.POST("/token/revoke", s.revokeToken)
	router.GET("/.well-known/jwks.json", s.getJWKS)

	s.HttpServer = &http.Server{
		Addr:    addr,
		Handler: router,
	}
	return s
}

// Start runs the server in a goroutine.
func (s *Server) Start() {
	go func() {
		if err := s.HttpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop(ctx context.Context) error {
	return s.HttpServer.Shutdown(ctx)
}

func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) issueToken(c *gin.Context) {
	var req struct {
		TenantID string `json:"tenant_id"`
		DeviceID string `json:"device_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	now := time.Now()
	accessToken, _ := s.createToken("access", req.TenantID, req.DeviceID, now.Add(15*time.Minute))
	refreshToken, _ := s.createToken("refresh", req.TenantID, req.DeviceID, now.Add(7*24*time.Hour))

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    15 * 60,
	})
}

func (s *Server) refreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	claims, err := s.VerifyAndParseToken(req.RefreshToken, "refresh")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	// Revoke the old refresh token
	s.revoked.Store(claims["jti"], true)

	now := time.Now()
	newAccessToken, _ := s.createToken("access", claims["tenant_id"].(string), claims["device_id"].(string), now.Add(15*time.Minute))
	newRefreshToken, _ := s.createToken("refresh", claims["tenant_id"].(string), claims["device_id"].(string), now.Add(7*24*time.Hour))

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    15 * 60,
	})
}

func (s *Server) revokeToken(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	claims, err := s.VerifyAndParseToken(req.Token, "") // Allow any type
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	s.revoked.Store(claims["jti"], true)
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) getJWKS(c *gin.Context) {
	// For HMAC, we don't expose a public key. Return an empty set.
	c.JSON(http.StatusOK, gin.H{"keys": []interface{}{}})
}
