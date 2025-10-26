// tests/unit/token_service_test.go
package unit

import (
   "context"
   "testing"
   "time"

   "github.com/stretchr/testify/require"
   "github.com/turtacn/cbc/internal/domain/models"
   "github.com/turtacn/cbc/internal/domain/service"
)

func TestIssueVerifyRefresh(t *testing.T) {
   keys := &staticKeyRepo{kid:"kid", key: []byte("secret")}
   black := &memBlack{}
   audit := &noopAudit{}
   s := service.NewTokenService(keys, black, audit, time.Minute, time.Hour)

   p, err := s.Issue(context.Background(), service.IssueInput{TenantID:"t", UserID:"u", DeviceID:"d"})
   require.NoError(t, err)

   vr, err := s.Verify(context.Background(), p.AccessToken, "access")
   require.NoError(t, err); require.Equal(t, "t", vr.Claims.TenantID)

   _, err = s.Refresh(context.Background(), p.RefreshToken)
   require.NoError(t, err)
   _, err = s.Refresh(context.Background(), p.RefreshToken)
   require.Error(t, err) // 已加入黑名单
}

type staticKeyRepo struct{ kid string; key []byte }
func (s *staticKeyRepo) ActiveKey() (*models.KeyMeta, []byte, error) { return &models.KeyMeta{KID:s.kid,Alg:"HS256"}, s.key, nil }
func (s *staticKeyRepo) FindByKID(kid string) (*models.KeyMeta, []byte, error) { return &models.KeyMeta{KID:kid,Alg:"HS256"}, s.key, nil }

type memBlack struct{ m map[string]bool }
func (b *memBlack) IsRevoked(jti string) (bool, error) { if b.m==nil { b.m=map[string]bool{} }; return b.m[jti], nil }
func (b *memBlack) Revoke(jti string) error { if b.m==nil { b.m=map[string]bool{} }; b.m[jti]=true; return nil }

type noopAudit struct{}
func (*noopAudit) Write(event string, payload map[string]any) error { return nil }
