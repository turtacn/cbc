// internal/infrastructure/ratelimit/middleware.go
package ratelimit

import (
   "net/http"
   "strconv"
   "time"

   "github.com/gin-gonic/gin"
   "github.com/redis/go-redis/v9"
)

func FixedWindow(rdb *redis.Client, limit int, window time.Duration, keyFunc func(*gin.Context) string) gin.HandlerFunc {
   return func(c *gin.Context) {
      key := "rl:" + keyFunc(c)
      pipe := rdb.TxPipeline()
      cnt := pipe.Incr(c, key)
      pipe.Expire(c, key, window)
      _, _ = pipe.Exec(c)
      if v := cnt.Val(); v > int64(limit) {
         c.Header("Retry-After", strconv.Itoa(int(window.Seconds())))
         c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limited"})
         return
      }
      c.Next()
   }
}
