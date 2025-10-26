// internal/domain/service/token_service.go
package service

import (
   "context"
   "errors"
   "time"

   "github.com/golang-jwt/jwt/v5"
   "github.com/google/uuid"
   "github.com/turtacn/cbc/internal/domain/models"
   "github.com/turtacn/cbc/internal/domain/repository"
)

type TokenService struct {
   keys     repository.KeyRepo
   black    repository.TokenBlacklist
   audit    repository.AuditRepo
   accessTTL  time.Duration
   refreshTTL time.Duration
}

func NewTokenService(keys repository.KeyRepo, black repository.TokenBlacklist, audit repository.AuditRepo, accessTTL, refreshTTL time.Duration) *TokenService {
   return &TokenService{keys: keys, black: black, audit: audit, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

type IssueInput struct {
   TenantID string
   UserID   string
   DeviceID string
   Scope    []string
}

type Pair struct {
   AccessToken  string
   RefreshToken string
}

func (s *TokenService) Issue(ctx context.Context, in IssueInput) (*Pair, error) {
   meta, key, err := s.keys.ActiveKey()
   if err != nil { return nil, err }

   now := time.Now()
   access := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
      "jti": uuid.NewString(),
      "sub": in.UserID,
      "tid": in.TenantID,
      "did": in.DeviceID,
      "scp": in.Scope,
      "typ": "access",
      "iat": now.Unix(),
      "exp": now.Add(s.accessTTL).Unix(),
   })
   access.Header["kid"] = meta.KID

   refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
      "jti": uuid.NewString(),
      "sub": in.UserID, "tid": in.TenantID, "did": in.DeviceID,
      "typ": "refresh", "iat": now.Unix(),
      "exp": now.Add(s.refreshTTL).Unix(),
   })
   refresh.Header["kid"] = meta.KID

   ak, err := access.SignedString(key); if err != nil { return nil, err }
   rk, err := refresh.SignedString(key); if err != nil { return nil, err }

   _ = s.audit.Write("issue_pair", map[string]any{"tid": in.TenantID, "uid": in.UserID, "did": in.DeviceID, "kid": meta.KID})
   return &Pair{AccessToken: ak, RefreshToken: rk}, nil
}

type VerifyResult struct {
   Claims models.TokenClaims
}

func (s *TokenService) Verify(ctx context.Context, tokenStr, expectedTyp string) (*VerifyResult, error) {
   parser := &jwt.Parser{}
   tok, parts, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
   if err != nil || len(parts) != 3 { return nil, errors.New("invalid token") }

   kid, _ := tok.Header["kid"].(string)
   meta, key, err := s.keys.FindByKID(kid)
   if err != nil || meta == nil { return nil, errors.New("unknown kid") }

   tok, err = parser.Parse(tokenStr, func(_ *jwt.Token) (interface{}, error) { return key, nil })
   if err != nil { return nil, err }

   claims := tok.Claims.(jwt.MapClaims)
   if expectedTyp != "" && claims["typ"] != expectedTyp {
      return nil, errors.New("wrong token type")
   }
   if time.Now().Unix() > int64(claims["exp"].(float64)) {
      return nil, errors.New("expired")
   }
   if revoked, _ := s.black.IsRevoked(claims["jti"].(string)); revoked {
      return nil, errors.New("revoked")
   }

   return &VerifyResult{
      Claims: models.TokenClaims{
         JTI: claims["jti"].(string),
         Sub: claims["sub"].(string),
         TenantID: claims["tid"].(string),
         DeviceID: claims["did"].(string),
         Scope: toStringSlice(claims["scp"]),
         Typ: claims["typ"].(string),
         Exp: int64(claims["exp"].(float64)),
         Iat: int64(claims["iat"].(float64)),
         KID: kid,
      },
   }, nil
}

func (s *TokenService) Refresh(ctx context.Context, refreshToken string) (*Pair, error) {
   v, err := s.Verify(ctx, refreshToken, "refresh")
   if err != nil { return nil, err }
   // 旧 refresh 的 jti 加入黑名单，防止重放
   _ = s.black.Revoke(v.Claims.JTI)
   return s.Issue(ctx, IssueInput{
      TenantID: v.Claims.TenantID, UserID: v.Claims.Sub, DeviceID: v.Claims.DeviceID,
      Scope: v.Claims.Scope,
   })
}

func (s *TokenService) Revoke(ctx context.Context, jti string) error {
   _ = s.audit.Write("revoke", map[string]any{"jti": jti})
   return s.black.Revoke(jti)
}

func toStringSlice(v any) []string {
   if v == nil { return nil }
   if s, ok := v.([]any); ok {
      out := make([]string, 0, len(s))
      for _, e := range s { out = append(out, e.(string)) }
      return out
   }
   if s, ok := v.([]string); ok { return s }
   return nil
}
