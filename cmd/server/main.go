// cmd/server/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/turtacn/cbc/internal/domain/service"
	postgresstore "github.com/turtacn/cbc/internal/infrastructure/persistence/postgres"
	redisstore "github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
	"github.com/turtacn/cbc/internal/infrastructure/ratelimit"
	httpapi "github.com/turtacn/cbc/internal/interfaces/http"
)

func main() {
	gin.SetMode(gin.ReleaseMode)

	// In a real application, the database connection string would come from a config file.
	dbpool, err := pgxpool.New(context.Background(), "postgres://user:password@localhost:5432/testdb")
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer dbpool.Close()

	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	keys := postgresstore.NewKeyRepo(dbpool)
	audit := postgresstore.NewAuditRepo(dbpool)
	tokens := service.NewTokenService(keys, redisstore.NewBlacklist(rdb), audit, 15*time.Minute, 24*time.Hour)
	srv := httpapi.New(tokens)

	// Add rate limiting middleware
	srv.Engine.Use(ratelimit.FixedWindow(rdb, 100, time.Minute, func(c *gin.Context) string {
		return c.ClientIP()
	}))

	log.Println("listening on :8080")
	_ = http.ListenAndServe(":8080", srv.Engine)
}
