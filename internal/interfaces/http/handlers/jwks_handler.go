// internal/interfaces/http/handlers/jwks_handler.go
package handlers

import (
"crypto/rsa"
"encoding/base64"
"math/big"
"net/http"

"github.com/gin-gonic/gin"
domain "github.com/turtacn/cbc/internal/domain/service"
"github.com/turtacn/cbc/pkg/errors"
"github.com/turtacn/cbc/pkg/logger"
)

type JWKSHandler struct {
crypto domain.CryptoService
logger logger.Logger
metrics HTTPMetrics
}

func NewJWKSHandler(crypto domain.CryptoService, log logger.Logger, m HTTPMetrics) *JWKSHandler {
return &JWKSHandler{crypto: crypto, logger: log, metrics: m}
}

func (h *JWKSHandler) GetJWKS(c *gin.Context) {
h.metrics.RecordRequestStart(c.Request.Context(), "jwks")

tenantID := c.Param("tenant_id")
if tenantID == "" {
c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
return
}

kid := c.Query("kid")
if kid == "" {
// 获取当前活跃 kid
_, currentKID, err := h.crypto.GetPrivateKey(c.Request.Context(), tenantID)
if err != nil {
h.logger.Error(c.Request.Context(), "get active kid failed", err, logger.String("tenant_id", tenantID))
c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get active kid"})
return
}
kid = currentKID
}

pub, err := h.crypto.GetPublicKey(c.Request.Context(), tenantID, kid)
if err != nil {
if errors.IsNotFoundError(err) {
c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
return
}
h.logger.Error(c.Request.Context(), "get public key failed", err,
logger.String("tenant_id", tenantID), logger.String("kid", kid))
c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get public key"})
return
}

jwk := rsaToJWK(pub, kid)
h.metrics.RecordRequestDuration(c.Request.Context(), "jwks", http.StatusOK, 0)
c.JSON(http.StatusOK, gin.H{"keys": []any{jwk}})
}

func rsaToJWK(pub *rsa.PublicKey, kid string) map[string]any {
// Base64URL (无填充)
n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
return map[string]any{
"kty": "RSA",
"use": "sig",
"alg": "RS256",
"kid": kid,
"n": n,
"e": e,
}
}
