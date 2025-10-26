// tests/e2e/auth_flow_test.go
package e2e

import (
   "bytes"
   "encoding/json"
   "net/http"
   "net/http/httptest"
   "testing"
   "time"

   "github.com/alicebob/miniredis/v2"
   "github.com/gin-gonic/gin"
   "github.com/redis/go-redis/v9"
   "github.com/stretchr/testify/require"
   "github.com/turtacn/cbc/internal/domain/models"
   "github.com/turtacn/cbc/internal/domain/service"
   httpapi "github.com/turtacn/cbc/internal/interfaces/http"
   redisstore "github.com/turtacn/cbc/internal/infrastructure/persistence/redis"
)

func TestAuthFlow(t *testing.T) {
   gin.SetMode(gin.TestMode)

   // Use miniredis to create an in-memory Redis server
   mr, err := miniredis.Run()
   require.NoError(t, err)
   defer mr.Close()

   rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
   black := redisstore.NewBlacklist(rdb)
   audit := &noopAudit{}

   keys := &staticKeyRepo{kid: "kid-1", key: []byte("secret-012345")}
   tokens := service.NewTokenService(keys, black, audit, 15*time.Minute, 24*time.Hour)

   srv := httpapi.New(tokens)
   ts := httptest.NewServer(srv.Engine)
   defer ts.Close()

   body := map[string]any{"tenant_id":"t1","user_id":"u1","device_id":"d1","scope":[]string{"read"}}
   bs,_ := json.Marshal(body)
   resp, err := http.Post(ts.URL+"/token/issue","application/json",bytes.NewReader(bs))
   require.NoError(t, err); require.Equal(t, 200, resp.StatusCode)
   var issue map[string]string; _ = json.NewDecoder(resp.Body).Decode(&issue)
   access := issue["access_token"]; refresh := issue["refresh_token"]

   req := map[string]any{"token": access, "typ":"access"}
   bs,_ = json.Marshal(req)
   vr, err := http.Post(ts.URL+"/token/verify","application/json",bytes.NewReader(bs))
   require.NoError(t, err); require.Equal(t, 200, vr.StatusCode)

   // refresh
   bs,_ = json.Marshal(map[string]string{"refresh_token": refresh})
   rp, err := http.Post(ts.URL+"/token/refresh","application/json",bytes.NewReader(bs))
   require.NoError(t, err); require.Equal(t, 200, rp.StatusCode)
   var newPair map[string]string; _ = json.NewDecoder(rp.Body).Decode(&newPair)
   require.NotEqual(t, access, newPair["access_token"])

   // revoke old refresh jti（由服务在刷新时已自动加入黑名单），验证旧 refresh 不能再次刷新
   rp2, _ := http.Post(ts.URL+"/token/refresh","application/json",bytes.NewReader(bs))
   require.Equal(t, 401, rp2.StatusCode)
}

type staticKeyRepo struct{ kid string; key []byte }
func (s *staticKeyRepo) ActiveKey() (*models.KeyMeta, []byte, error) { return &models.KeyMeta{KID:s.kid,Alg:"HS256"}, s.key, nil }
func (s *staticKeyRepo) CanaryKey() (*models.KeyMeta, []byte, error) { return nil, nil, nil } // No canary key in this test repo
func (s *staticKeyRepo) FindByKID(kid string) (*models.KeyMeta, []byte, error) { return &models.KeyMeta{KID:kid,Alg:"HS256"}, s.key, nil }

type noopAudit struct{}
func (*noopAudit) Write(event string, payload map[string]any) error { return nil }
