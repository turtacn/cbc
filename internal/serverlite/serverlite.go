package serverlite

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/internal/domain/service"
	redisstore "github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	httpapi "github.com/turtacn/cbc/internal/interfaces/http"
)

// Server is a lightweight, in-memory auth server for E2E testing.
type Server struct {
	HttpServer *http.Server
}

// NewServer creates and configures a new server.
func NewServer(addr string, signingKey []byte) *Server {
	gin.SetMode(gin.TestMode)

	// Use in-memory implementations for dependencies
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"}) // Assumes a local Redis is running for tests
	blacklist := redisstore.NewBlacklist(rdb)
	audit := &noopAudit{}
	keys := &staticKeyRepo{kid: "kid-1", key: signingKey}

	tokenService := service.NewTokenService(keys, blacklist, audit, 15*time.Minute, 24*time.Hour)
	httpServer := httpapi.New(tokenService)

	return &Server{
		HttpServer: &http.Server{
			Addr:    addr,
			Handler: httpServer.Engine,
		},
	}
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

// staticKeyRepo is a simple in-memory key repository for testing.
type staticKeyRepo struct {
	kid string
	key []byte
}

func (s *staticKeyRepo) ActiveKey() (*models.KeyMeta, []byte, error) {
	return &models.KeyMeta{KID: s.kid, Alg: "HS256"}, s.key, nil
}

func (s *staticKeyRepo) CanaryKey() (*models.KeyMeta, []byte, error) {
	return nil, nil, nil // No canary key in this test repo
}

func (s *staticKeyRepo) FindByKID(kid string) (*models.KeyMeta, []byte, error) {
	return &models.KeyMeta{KID: kid, Alg: "HS256"}, s.key, nil
}

// noopAudit is a no-op audit repository for testing.
type noopAudit struct{}

func (*noopAudit) Write(event string, payload map[string]any) error { return nil }
