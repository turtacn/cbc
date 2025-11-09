// internal/interfaces/http/handlers/jwks_handler.go
package handlers

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

type JWKSHandler struct {
	kms     service.KeyManagementService
	logger  logger.Logger
	metrics HTTPMetrics
}

func NewJWKSHandler(kms service.KeyManagementService, log logger.Logger, m HTTPMetrics) *JWKSHandler {
	return &JWKSHandler{kms: kms, logger: log, metrics: m}
}

func (h *JWKSHandler) GetJWKS(c *gin.Context) {
	h.metrics.RecordRequestStart(c.Request.Context(), "jwks")

	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	publicKeys, err := h.kms.GetTenantPublicKeys(c.Request.Context(), tenantID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "keys not found"})
			return
		}
		h.logger.Error(c.Request.Context(), "get public keys failed", err,
			logger.String("tenant_id", tenantID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get public keys"})
		return
	}

	jwks := make([]map[string]interface{}, 0, len(publicKeys))
	for kid, pub := range publicKeys {
		jwks = append(jwks, rsaToJWK(pub, kid))
	}

	h.metrics.RecordRequestDuration(c.Request.Context(), "jwks", http.StatusOK, 0)
	c.JSON(http.StatusOK, gin.H{"keys": jwks})
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
		"n":   n,
		"e":   e,
	}
}
