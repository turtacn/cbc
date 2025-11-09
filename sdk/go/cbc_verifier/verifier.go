package cbc_verifier

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

var (
	ErrKidNotFound      = errors.New("kid not found in JWKS")
	ErrNoKeysFound      = errors.New("no keys found in JWKS response")
	ErrUnsupportedAlg   = errors.New("unsupported algorithm")
	ErrInvalidToken     = errors.New("invalid token")
)

// JWKS_Refresher is a thread-safe client for fetching and caching JWKS.
type JWKS_Refresher struct {
	jwksUrl      string
	l1Cache      map[string]*rsa.PublicKey
	cacheMutex   sync.RWMutex
	lastETag     string
	httpClient   *http.Client
}

// NewJWKS_Refresher creates a new JWKS_Refresher.
func NewJWKS_Refresher(jwksUrl string) *JWKS_Refresher {
	return &JWKS_Refresher{
		jwksUrl:      jwksUrl,
		l1Cache:      make(map[string]*rsa.PublicKey),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

// FetchJWKS fetches and caches the JWKS.
func (r *JWKS_Refresher) FetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.jwksUrl, nil)
	if err != nil {
		return err
	}

	r.cacheMutex.RLock()
	if r.lastETag != "" {
		req.Header.Set("If-None-Match", r.lastETag)
	}
	r.cacheMutex.RUnlock()

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil // Cache is still valid
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status code %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	if len(jwks.Keys) == 0 {
		return ErrNoKeysFound
	}

	newCache := make(map[string]*rsa.PublicKey)
	for _, key := range jwks.Keys {
		if key.Algorithm != string(jose.RS256) && key.Algorithm != string(jose.RS384) && key.Algorithm != string(jose.RS512) {
			continue // Skip unsupported algorithms
		}
		if pubKey, ok := key.Key.(*rsa.PublicKey); ok {
			newCache[key.KeyID] = pubKey
		}
	}

	r.cacheMutex.Lock()
	r.l1Cache = newCache
	r.lastETag = resp.Header.Get("ETag")
	r.cacheMutex.Unlock()

	return nil
}

// Verify verifies a JWT string.
func (r *JWKS_Refresher) Verify(ctx context.Context, tokenString string) (*jwt.Token, error) {
	// First, parse the token without verification to get the kid
	unverifiedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	kid, ok := unverifiedToken.Header["kid"].(string)
	if !ok {
		return nil, ErrKidNotFound
	}

	// Try to get the key from the cache
	r.cacheMutex.RLock()
	publicKey, found := r.l1Cache[kid]
	r.cacheMutex.RUnlock()

	if found {
		// Key found, try to verify
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err == nil && token.Valid {
			return token, nil
		}
	}

	// If key not found or verification failed, refresh the JWKS and retry
	if err := r.FetchJWKS(ctx); err != nil {
		return nil, err
	}

	r.cacheMutex.RLock()
	publicKey, found = r.l1Cache[kid]
	r.cacheMutex.RUnlock()

	if !found {
		return nil, ErrKidNotFound
	}

	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
}
