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

// JWKSHandler handles HTTP requests for retrieving a tenant's JSON Web Key Set (JWKS).
// JWKSHandler 处理用于检索租户的 JSON Web Key Set (JWKS) 的 HTTP 请求。
type JWKSHandler struct {
	kms    service.KeyManagementService
	logger logger.Logger
}

// NewJWKSHandler creates a new instance of the JWKSHandler.
// NewJWKSHandler 创建一个新的 JWKSHandler 实例。
func NewJWKSHandler(kms service.KeyManagementService, log logger.Logger) *JWKSHandler {
	return &JWKSHandler{kms: kms, logger: log}
}

// GetJWKS is the handler for the JWKS endpoint.
// It retrieves all active public keys for a given tenant and formats them into a JWKS response.
// GET /api/v1/jwks/:tenant_id
// GetJWKS 是 JWKS 端点的处理程序。
// 它检索给定租户的所有活动公钥，并将它们格式化为 JWKS 响应。
func (h *JWKSHandler) GetJWKS(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id is required"})
		return
	}

	// Retrieve all active public keys for the specified tenant.
	publicKeys, err := h.kms.GetTenantPublicKeys(c.Request.Context(), tenantID)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "keys not found for the specified tenant"})
			return
		}
		h.logger.Error(c.Request.Context(), "failed to get tenant public keys", err,
			logger.String("tenant_id", tenantID))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error while fetching keys"})
		return
	}

	// Convert the RSA public keys into the JWK format.
	jwks := make([]map[string]interface{}, 0, len(publicKeys))
	for kid, pub := range publicKeys {
		jwks = append(jwks, rsaToJWK(pub, kid))
	}

	c.JSON(http.StatusOK, gin.H{"keys": jwks})
}

// rsaToJWK converts an *rsa.PublicKey into a JWK (JSON Web Key) map representation.
// This format is standardized for publishing public keys.
// rsaToJWK 将 *rsa.PublicKey 转换成 JWK (JSON Web Key) 的 map 表示。
// 此格式是用于发布公钥的标准化格式。
func rsaToJWK(pub *rsa.PublicKey, kid string) map[string]interface{} {
	// Encode the modulus (n) and exponent (e) using Base64URL encoding without padding.
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig", // Key usage is for signing.
		"alg": "RS256",
		"kid": kid, // Key ID.
		"n":   n,   // Modulus.
		"e":   e,   // Exponent.
	}
}
