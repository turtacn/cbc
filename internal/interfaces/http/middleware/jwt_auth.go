package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/turtacn/cbc/internal/domain/service"
	"github.com/turtacn/cbc/pkg/logger"
)

// extractBearer is a helper function that parses the `Authorization` header
// to extract the bearer token string. It returns an empty string if the header is missing or malformed.
// extractBearer 是一个辅助函数，用于从 `Authorization` 标头中解析持有者令牌字符串。
// 如果标头缺失或格式错误，则返回一个空字符串。
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

// RequireJWT returns a Gin middleware that enforces JWT-based authentication for a route.
// It performs a multi-step validation:
// 1. Extracts the token from the `Authorization` header.
// 2. Parses the token to get the tenant ID.
// 3. Verifies the token's signature and claims using the KeyManagementService.
// 4. Checks if the token's JTI (JWT ID) has been revoked by checking the blacklist.
// If all checks pass, it injects the verified claims into the context for downstream handlers.
// RequireJWT 返回一个 Gin 中间件，该中间件为路由强制执行基于 JWT 的身份验证。
// 它执行多步验证：
// 1. 从 `Authorization` 标头中提取令牌。
// 2. 解析令牌以获取租户 ID。
// 3. 使用 KeyManagementService 验证令牌的签名和声明。
// 4. 通过检查黑名单来检查令牌的 JTI (JWT ID) 是否已被吊销。
// 如果所有检查都通过，它会将经过验证的声明注入到上下文中以供下游处理程序使用。
func RequireJWT(kms service.KeyManagementService, bl service.TokenBlacklistStore, log logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenStr := extractBearer(c.Request.Header.Get("Authorization"))
		if tokenStr == "" {
			log.Warn(c, "Authorization header is missing or malformed")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// First, parse the token without verification to safely extract claims like tenant_id.
		parser := jwt.Parser{}
		token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
		if err != nil {
			log.Warn(c, "Failed to parse token structure", logger.Error(err))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Warn(c, "Failed to cast token claims")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tenantID, ok := claims["tenant_id"].(string)
		if !ok || tenantID == "" {
			log.Warn(c, "tenant_id claim is missing or invalid in token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Now, perform full verification of the token's signature and standard claims (exp, nbf, etc.).
		verifiedClaims, err := kms.VerifyJWT(c.Request.Context(), tokenStr, tenantID)
		if err != nil {
			log.Warn(c, "JWT signature or claim verification failed", logger.Error(err))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		jti, ok := verifiedClaims["jti"].(string)
		if !ok || jti == "" {
			log.Warn(c, "jti claim is missing from verified token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Check if the token has been explicitly revoked.
		revoked, err := bl.IsRevoked(c.Request.Context(), tenantID, jti)
		if err != nil {
			log.Error(c, "Failed to check token blacklist", err)
			c.AbortWithStatus(http.StatusInternalServerError) // Internal error, not an auth failure.
			return
		}
		if revoked {
			log.Warn(c, "Authentication attempt with a revoked token", logger.String("jti", jti))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			log.Warn(c, "kid header is missing from token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// If all checks pass, enrich the context for downstream handlers.
		c.Set("claims", verifiedClaims)
		c.Set("kid", kid)
		c.Next()
	}
}
