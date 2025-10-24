// Package crypto provides JWT token management services including generation,
// verification, and public key distribution.
package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/turtacn/cbc/internal/domain/models"
	"github.com/turtacn/cbc/pkg/constants"
	"github.com/turtacn/cbc/pkg/errors"
	"github.com/turtacn/cbc/pkg/logger"
)

// JWTManager implements JWT token generation and verification.
type JWTManager struct {
	keyManager *KeyManager
	logger     logger.Logger
	config     *JWTConfig
}

// JWTConfig holds JWT manager configuration.
type JWTConfig struct {
	// Issuer is the JWT issuer claim
	Issuer string
	// Audience is the JWT audience claim
	Audience []string
	// DefaultTTL is the default token validity duration
	DefaultTTL time.Duration
	// RefreshTTL is the refresh token validity duration
	RefreshTTL time.Duration
	// ClockSkew is the acceptable time difference for token validation
	ClockSkew time.Duration
	// Algorithm is the signing algorithm (RS256 or ES256)
	Algorithm string
}

// DefaultJWTConfig returns default JWT configuration.
func DefaultJWTConfig() *JWTConfig {
	return &JWTConfig{
		Issuer:     "cbc-auth-service",
		Audience:   []string{"cbc-api"},
		DefaultTTL: 15 * time.Minute,
		RefreshTTL: 7 * 24 * time.Hour,
		ClockSkew:  5 * time.Minute,
		Algorithm:  "RS256",
	}
}

// CustomClaims represents JWT custom claims.
type CustomClaims struct {
	jwt.RegisteredClaims
	TenantID  string                 `json:"tenant_id,omitempty"`
	DeviceID  string                 `json:"device_id,omitempty"`
	TokenType string                 `json:"token_type,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`           // Key Type
	Use string `json:"use,omitempty"` // Public Key Use
	Kid string `json:"kid,omitempty"` // Key ID
	Alg string `json:"alg,omitempty"` // Algorithm
	N   string `json:"n,omitempty"`   // RSA Modulus
	E   string `json:"e,omitempty"`   // RSA Exponent
	Crv string `json:"crv,omitempty"` // EC Curve
	X   string `json:"x,omitempty"`   // EC X Coordinate
	Y   string `json:"y,omitempty"`   // EC Y Coordinate
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewJWTManager creates a new JWT manager instance.
//
// Parameters:
//   - keyManager: Key manager for key operations
//   - config: JWT configuration
//   - log: Logger instance
//
// Returns:
//   - *JWTManager: Initialized JWT manager
//   - error: Initialization error if any
func NewJWTManager(
	keyManager *KeyManager,
	config *JWTConfig,
	log logger.Logger,
) (*JWTManager, error) {
	if keyManager == nil {
		return nil, errors.New(errors.CodeInvalidArgument, "key manager is required")
	}

	if config == nil {
		config = DefaultJWTConfig()
	}

	jm := &JWTManager{
		keyManager: keyManager,
		logger:     log,
		config:     config,
	}

	log.Info("JWT manager initialized",
		"issuer", config.Issuer,
		"algorithm", config.Algorithm,
		"default_ttl", config.DefaultTTL,
	)

	return jm, nil
}

// GenerateJWT generates a new JWT token.
//
// Parameters:
//   - ctx: Context for timeout control
//   - token: Token model with metadata
//
// Returns:
//   - string: Generated JWT token
//   - error: Generation error if any
func (jm *JWTManager) GenerateJWT(ctx context.Context, token *models.Token) (string, error) {
	if token.TenantID == "" {
		return "", errors.New(errors.CodeInvalidArgument, "tenant ID is required")
	}

	// Get active key for tenant
	keyPair, err := jm.keyManager.GetActiveKeyForTenant(ctx, token.TenantID)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to get signing key")
	}

	// Determine token type and TTL
	tokenType := constants.TokenTypeAccess
	ttl := jm.config.DefaultTTL
	if token.TokenType == constants.TokenTypeRefresh {
		tokenType = constants.TokenTypeRefresh
		ttl = jm.config.RefreshTTL
	}

	// Build claims
	now := time.Now()
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        token.ID,
			Issuer:    jm.config.Issuer,
			Subject:   token.UserID,
			Audience:  jwt.ClaimStrings(jm.config.Audience),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		TenantID:  token.TenantID,
		DeviceID:  token.DeviceID,
		TokenType: tokenType,
		Metadata:  token.Metadata,
	}

	// Parse private key
	privateKey, err := jm.parsePrivateKey(keyPair.PrivateKey, keyPair.Algorithm)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to parse private key")
	}

	// Determine signing method
	var signingMethod jwt.SigningMethod
	switch keyPair.Algorithm {
	case RSA2048, RSA4096:
		signingMethod = jwt.SigningMethodRS256
	case ECDSAP256, ECDSAP384:
		signingMethod = jwt.SigningMethodES256
	default:
		return "", errors.New(errors.CodeInternal, "unsupported algorithm: %s", keyPair.Algorithm)
	}

	// Create token with kid header
	jwtToken := jwt.NewWithClaims(signingMethod, claims)
	jwtToken.Header["kid"] = keyPair.ID

	// Sign token
	signedToken, err := jwtToken.SignedString(privateKey)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to sign JWT")
	}

	jm.logger.Debug("JWT generated",
		"token_id", token.ID,
		"tenant_id", token.TenantID,
		"key_id", keyPair.ID,
		"token_type", tokenType,
		"expires_at", claims.ExpiresAt.Time,
	)

	return signedToken, nil
}

// VerifyJWT verifies a JWT token and returns its claims.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tokenString: JWT token string
//
// Returns:
//   - *CustomClaims: Parsed claims
//   - error: Verification error if any
func (jm *JWTManager) VerifyJWT(ctx context.Context, tokenString string) (*CustomClaims, error) {
	// Parse token to get header (without verification)
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &CustomClaims{})
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthenticated, "failed to parse JWT")
	}

	// Get key ID from header
	kidInterface, ok := token.Header["kid"]
	if !ok {
		return nil, errors.New(errors.CodeUnauthenticated, "missing kid in JWT header")
	}
	kid, ok := kidInterface.(string)
	if !ok {
		return nil, errors.New(errors.CodeUnauthenticated, "invalid kid in JWT header")
	}

	// Get public key
	keyPair, err := jm.keyManager.GetKeyPair(ctx, kid)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthenticated, "failed to get verification key")
	}

	// Check if key is valid (active or deprecated within grace period)
	now := time.Now()
	if keyPair.Status == KeyStatusExpired || now.After(keyPair.ExpiresAt) {
		return nil, errors.New(errors.CodeUnauthenticated, "signing key has expired")
	}

	// Parse public key
	publicKey, err := jm.parsePublicKey(keyPair.PublicKey, keyPair.Algorithm)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "failed to parse public key")
	}

	// Verify token with proper validation
	claims := &CustomClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		switch keyPair.Algorithm {
		case RSA2048, RSA4096:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, errors.New(errors.CodeUnauthenticated, "unexpected signing method: %v", token.Header["alg"])
			}
		case ECDSAP256, ECDSAP384:
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, errors.New(errors.CodeUnauthenticated, "unexpected signing method: %v", token.Header["alg"])
			}
		}
		return publicKey, nil
	}, jwt.WithLeeway(jm.config.ClockSkew))

	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthenticated, "failed to verify JWT")
	}

	if !parsedToken.Valid {
		return nil, errors.New(errors.CodeUnauthenticated, "invalid JWT token")
	}

	// Validate claims
	if err := jm.validateClaims(claims); err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthenticated, "invalid JWT claims")
	}

	jm.logger.Debug("JWT verified",
		"token_id", claims.ID,
		"tenant_id", claims.TenantID,
		"key_id", kid,
		"subject", claims.Subject,
	)

	return claims, nil
}

// GetPublicKey retrieves the public key for a tenant in JWK format.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//
// Returns:
//   - string: Public key in JWK format
//   - error: Retrieval error if any
func (jm *JWTManager) GetPublicKey(ctx context.Context, tenantID string) (string, error) {
	// Get active key for tenant
	keyPair, err := jm.keyManager.GetActiveKeyForTenant(ctx, tenantID)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeNotFound, "failed to get public key")
	}

	// Convert to JWK
	jwk, err := jm.publicKeyToJWK(keyPair)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to convert to JWK")
	}

	// Marshal to JSON
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to marshal JWK")
	}

	return string(jwkJSON), nil
}

// GetPublicKeySet retrieves all public keys for a tenant as JWKS.
//
// Parameters:
//   - ctx: Context for timeout control
//   - tenantID: Tenant identifier
//
// Returns:
//   - string: JWKS JSON string
//   - error: Retrieval error if any
func (jm *JWTManager) GetPublicKeySet(ctx context.Context, tenantID string) (string, error) {
	// Get all keys for tenant
	metadata, err := jm.keyManager.ListTenantKeys(ctx, tenantID)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to list tenant keys")
	}

	jwks := JWKS{
		Keys: make([]JWK, 0, len(metadata)),
	}

	// Convert each active/deprecated key to JWK
	for _, meta := range metadata {
		if meta.Status == KeyStatusExpired {
			continue
		}

		keyPair, err := jm.keyManager.GetKeyPair(ctx, meta.ID)
		if err != nil {
			jm.logger.Warn("Failed to load key for JWKS",
				"key_id", meta.ID,
				"error", err,
			)
			continue
		}

		jwk, err := jm.publicKeyToJWK(keyPair)
		if err != nil {
			jm.logger.Warn("Failed to convert key to JWK",
				"key_id", meta.ID,
				"error", err,
			)
			continue
		}

		jwks.Keys = append(jwks.Keys, *jwk)
	}

	// Marshal to JSON
	jwksJSON, err := json.Marshal(jwks)
	if err != nil {
		return "", errors.Wrap(err, errors.CodeInternal, "failed to marshal JWKS")
	}

	return string(jwksJSON), nil
}

// RefreshToken refreshes an existing token.
//
// Parameters:
//   - ctx: Context for timeout control
//   - refreshToken: Refresh token string
//
// Returns:
//   - *models.Token: New token model
//   - error: Refresh error if any
func (jm *JWTManager) RefreshToken(ctx context.Context, refreshToken string) (*models.Token, error) {
	// Verify refresh token
	claims, err := jm.VerifyJWT(ctx, refreshToken)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeUnauthenticated, "invalid refresh token")
	}

	// Check token type
	if claims.TokenType != constants.TokenTypeRefresh {
		return nil, errors.New(errors.CodeInvalidArgument, "not a refresh token")
	}

	// Create new token
	token := &models.Token{
		ID:        generateTokenID(),
		UserID:    claims.Subject,
		TenantID:  claims.TenantID,
		DeviceID:  claims.DeviceID,
		TokenType: constants.TokenTypeAccess,
		Metadata:  claims.Metadata,
		CreatedAt: time.Now(),
	}

	return token, nil
}

// parsePrivateKey parses a PEM-encoded private key.
func (jm *JWTManager) parsePrivateKey(privateKeyPEM string, algorithm KeyAlgorithm) (interface{}, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch algorithm {
	case RSA2048, RSA4096:
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an RSA private key")
			}
			return rsaKey, nil
		}
		return privateKey, nil

	case ECDSAP256, ECDSAP384:
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
			}
			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("not an ECDSA private key")
			}
			return ecKey, nil
		}
		return privateKey, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// parsePublicKey parses a PEM-encoded public key.
func (jm *JWTManager) parsePublicKey(publicKeyPEM string, algorithm KeyAlgorithm) (interface{}, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch algorithm {
	case RSA2048, RSA4096:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		return rsaKey, nil

	case ECDSAP256, ECDSAP384:
		ecKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an ECDSA public key")
		}
		return ecKey, nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// publicKeyToJWK converts a public key to JWK format.
func (jm *JWTManager) publicKeyToJWK(keyPair *KeyPair) (*JWK, error) {
	publicKey, err := jm.parsePublicKey(keyPair.PublicKey, keyPair.Algorithm)
	if err != nil {
		return nil, err
	}

	jwk := &JWK{
		Kid: keyPair.ID,
		Use: "sig",
	}

	switch keyPair.Algorithm {
	case RSA2048, RSA4096:
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid RSA public key")
		}

		jwk.Kty = "RSA"
		jwk.Alg = "RS256"
		jwk.N = base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())

	case ECDSAP256, ECDSAP384:
		ecKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid ECDSA public key")
		}

		jwk.Kty = "EC"
		jwk.Alg = "ES256"
		jwk.Crv = ecKey.Curve.Params().Name
		jwk.X = base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes())

	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", keyPair.Algorithm)
	}

	return jwk, nil
}

// validateClaims validates JWT claims.
func (jm *JWTManager) validateClaims(claims *CustomClaims) error {
	// Validate issuer
	if claims.Issuer != jm.config.Issuer {
		return fmt.Errorf("invalid issuer: expected %s, got %s", jm.config.Issuer, claims.Issuer)
	}

	// Validate audience
	validAudience := false
	for _, aud := range jm.config.Audience {
		for _, claimAud := range claims.Audience {
			if claimAud == aud {
				validAudience = true
				break
			}
		}
		if validAudience {
			break
		}
	}
	if !validAudience {
		return fmt.Errorf("invalid audience")
	}

	// Time-based validations are handled by jwt library

	return nil
}

// generateTokenID generates a unique token ID.
func generateTokenID() string {
	return fmt.Sprintf("tok_%d_%s", time.Now().Unix(), randomString(16))
}

// randomString generates a random string of specified length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

// Close closes the JWT manager.
func (jm *JWTManager) Close() error {
	jm.logger.Info("JWT manager closed")
	return nil
}

//Personal.AI order the ending
