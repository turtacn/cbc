package serverlite

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (s *Server) createToken(tokenType, tenantID, deviceID string, expiresAt time.Time) (string, error) {
	claims := map[string]interface{}{
		"typ":       tokenType,
		"tenant_id": tenantID,
		"device_id": deviceID,
		"jti":       uuid.NewString(),
		"exp":       expiresAt.Unix(),
	}

	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsBytes)

	signingInput := fmt.Sprintf("%s.%s", encodedHeader, encodedClaims)

	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(signingInput))
	signature := mac.Sum(nil)

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("%s.%s.%s", encodedHeader, encodedClaims, encodedSignature), nil
}

func (s *Server) VerifyAndParseToken(tokenString, expectedType string) (map[string]interface{}, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Verify signature
	signingInput := fmt.Sprintf("%s.%s", parts[0], parts[1])
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(signingInput))
	expectedMAC := mac.Sum(nil)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature")
	}

	if !hmac.Equal(signature, expectedMAC) {
		return nil, fmt.Errorf("signature mismatch")
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid claims")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid claims json")
	}

	// Validate claims
	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return nil, fmt.Errorf("token expired")
		}
	} else {
		return nil, fmt.Errorf("exp claim missing")
	}

	if expectedType != "" {
		if typ, ok := claims["typ"].(string); ok {
			if typ != expectedType {
				return nil, fmt.Errorf("invalid token type")
			}
		} else {
			return nil, fmt.Errorf("typ claim missing")
		}
	}

	if jti, ok := claims["jti"].(string); ok {
		if _, revoked := s.revoked.Load(jti); revoked {
			return nil, fmt.Errorf("token revoked")
		}
	} else {
		return nil, fmt.Errorf("jti claim missing")
	}

	return claims, nil
}
