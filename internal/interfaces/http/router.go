// internal/interfaces/http/router.go
package httpapi

import (
   "net/http"
   "time"

   "github.com/gin-gonic/gin"
   "github.com/turtacn/cbc/internal/domain/service"
)

type Server struct {
   Engine *gin.Engine
   tokens *service.TokenService
}

func New(tokens *service.TokenService) *Server {
   r := gin.Default()
   s := &Server{Engine: r, tokens: tokens}

   r.GET("/healthz", func(c *gin.Context){ c.JSON(http.StatusOK, gin.H{"ok": true}) })

   r.POST("/token/issue", s.issue)
   r.POST("/token/refresh", s.refresh)
   r.POST("/token/revoke", s.revoke)
   r.POST("/token/verify", s.verify)
   return s
}

type issueReq struct {
   TenantID string   `json:"tenant_id" binding:"required"`
   UserID   string   `json:"user_id" binding:"required"`
   DeviceID string   `json:"device_id" binding:"required"`
   Scope    []string `json:"scope"`
}

func (s *Server) issue(c *gin.Context) {
   var in issueReq
   if err := c.ShouldBindJSON(&in); err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
   }
   pair, err := s.tokens.Issue(c, service.IssueInput{
      TenantID: in.TenantID, UserID: in.UserID, DeviceID: in.DeviceID, Scope: in.Scope,
   })
   if err != nil { c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return }
   c.JSON(http.StatusOK, gin.H{"access_token": pair.AccessToken, "refresh_token": pair.RefreshToken, "expires_in": int((15*time.Minute).Seconds())})
}

func (s *Server) refresh(c *gin.Context) {
   var body struct{ RefreshToken string `json:"refresh_token" binding:"required"` }
   if err := c.ShouldBindJSON(&body); err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
   }
   pair, err := s.tokens.Refresh(c, body.RefreshToken)
   if err != nil { c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()}); return }
   c.JSON(http.StatusOK, gin.H{"access_token": pair.AccessToken, "refresh_token": pair.RefreshToken})
}

func (s *Server) verify(c *gin.Context) {
	var body struct {
		Token string `json:"token" binding:"required"`
		Typ   string `json:"typ" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	res, err := s.tokens.Verify(c, body.Token, body.Typ)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"valid": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"valid": true, "claims": res.Claims})
}

func (s *Server) revoke(c *gin.Context) {
   var body struct{ JTI string `json:"jti" binding:"required"` }
   if err := c.ShouldBindJSON(&body); err != nil {
      c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}); return
   }
   if err := s.tokens.Revoke(c, body.JTI); err != nil {
      c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()}); return
   }
   c.JSON(http.StatusOK, gin.H{"ok": true})
}
