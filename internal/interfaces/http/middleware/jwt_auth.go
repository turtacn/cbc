package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// extractBearer extracts the token from the Authorization header.
func extractBearer(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

// RequireJWT is a middleware to protect routes that require a valid JWT.
func RequireJWT(crypto service.CryptoService, bl service.TokenBlacklistStore, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractBearer(c.Request.Header.Get("Authorization"))
		if tokenStr == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// First, parse the token without verification to extract tenant_id and kid.
		parser := jwt.Parser{}
		token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
		if err != nil {
			log.Warn(c, "Failed to parse token unverified", logger.Error(err))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Warn(c, "Failed to cast claims to MapClaims")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tenantID, ok := claims["tenant_id"].(string)
		if !ok || tenantID == "" {
			log.Warn(c, "tenant_id claim is missing or invalid")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Now, verify the token using the CryptoService, which will check the signature.
		verifiedClaims, err := crypto.VerifyJWT(c.Request.Context(), tokenStr, tenantID)
		if err != nil {
			log.Warn(c, "JWT verification failed", logger.Error(err))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		jti, ok := verifiedClaims["jti"].(string)
		if !ok || jti == "" {
			log.Warn(c, "jti claim is missing from verified token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Check if the token is in the blacklist.
		revoked, err := bl.IsRevoked(c.Request.Context(), tenantID, jti)
		if err != nil {
			log.Error(c, "Failed to check token blacklist", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if revoked {
			log.Warn(c, "Access attempt with revoked token", logger.String("jti", jti))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		kid, ok := token.Header["kid"].(string)
        if !ok {
             log.Warn(c, "kid header is missing")
			 c.AbortWithStatus(http.StatusUnauthorized)
			 return
        }

		// Set claims and other info in the context for downstream handlers.
		c.Set("claims", verifiedClaims)
		c.Set("kid", kid)
		c.Next()
	}
}
