// Package service provides domain services for the application.
package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWTCryptoService is a concrete implementation of CryptoService using JWT.
type JWTCryptoService struct {
	issuer         string
	expiration     time.Duration
	keys           map[string]*rsa.PrivateKey
	currentKid     map[string]string
	mu             sync.RWMutex
}

// NewJWTCryptoService creates a new JWTCryptoService.
func NewJWTCryptoService(issuer string, expiration time.Duration) (CryptoService, error) {
	return &JWTCryptoService{
		issuer:     issuer,
		expiration: expiration,
		keys:       make(map[string]*rsa.PrivateKey),
		currentKid: make(map[string]string),
	}, nil
}

// GetPrivateKey returns the private key for a given tenant.
func (s *JWTCryptoService) GetPrivateKey(ctx context.Context, tenantID string) (*rsa.PrivateKey, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	kid, ok := s.currentKid[tenantID]
	if !ok {
		// If no key, generate one
		newKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, "", err
		}
		newKid := "kid-" + uuid.New().String()
		s.keys[newKid] = newKey
		s.currentKid[tenantID] = newKid
		return newKey, newKid, nil
	}
	return s.keys[kid], kid, nil
}

// GetPublicKey returns the public key for a given kid.
func (s *JWTCryptoService) GetPublicKey(ctx context.Context, tenantID, kid string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key not found for kid: %s", kid)
	}
	return &key.PublicKey, nil
}

// ParseJWTClaimsUnverified parses a JWT string without verification and returns the claims.
// This is useful for tests or when you need to inspect the token before validation.
func ParseJWTClaimsUnverified(tokenString string) (jwt.MapClaims, error) {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	return claims, nil
}


// --- Unimplemented methods to satisfy the interface ---

func (s *JWTCryptoService) EncryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *JWTCryptoService) DecryptSensitiveData(ctx context.Context, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *JWTCryptoService) GenerateJWT(ctx context.Context, tenantID string, claims jwt.Claims) (string, string, error) {
    privateKey, kid, err := s.GetPrivateKey(ctx, tenantID)
    if err != nil {
        return "", "", err
    }
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    token.Header["kid"] = kid
    signedToken, err := token.SignedString(privateKey)
    return signedToken, kid, err
}


func (s *JWTCryptoService) VerifyJWT(ctx context.Context, tokenString string, tenantID string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}
		return s.GetPublicKey(ctx, tenantID, kid)
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *JWTCryptoService) RotateKey(ctx context.Context, tenantID string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

var _ CryptoService = (*JWTCryptoService)(nil)

// Helper function to extract claims for the middleware test
func ParseJWTClaims(tokenString string, crypto CryptoService) (jwt.MapClaims, string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not present in header")
		}
		claims := token.Claims.(jwt.MapClaims)
		tenantID := claims["tenant_id"].(string)
		return crypto.GetPublicKey(context.TODO(), tenantID, kid)
	})
	if err != nil {
		return nil, "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, token.Header["kid"].(string), nil
	}
	return nil, "", fmt.Errorf("invalid token")
}
