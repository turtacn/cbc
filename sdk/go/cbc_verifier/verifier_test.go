package cbc_verifier_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/turtacn/cbc/sdk/go/cbc_verifier"
	"gopkg.in/square/go-jose.v2"
)

func TestJWKS_Refresher_Verify(t *testing.T) {
	// Generate a test key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	publicKey := &privateKey.PublicKey

	jwk1 := jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     "test-kid-1",
		Algorithm: "RS256",
		Use:       "sig",
	}

	// State for the mock server
	var mu sync.Mutex
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk1},
	}
	etag := `"etag-1"`

	// Mock JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	refresher := cbc_verifier.NewJWKS_Refresher(server.URL)

	// Create a test token
	token1 := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "test"})
	token1.Header["kid"] = "test-kid-1"
	tokenString1, err := token1.SignedString(privateKey)
	assert.NoError(t, err)

	// --- Test Cases ---

	t.Run("first verification should fetch JWKS and succeed", func(t *testing.T) {
		_, err := refresher.Verify(context.Background(), tokenString1)
		assert.NoError(t, err)
	})

	t.Run("second verification with same kid should use cache and succeed", func(t *testing.T) {
		_, err := refresher.Verify(context.Background(), tokenString1)
		assert.NoError(t, err)
	})

	t.Run("verification with unknown kid should fail initially, then refresh and succeed", func(t *testing.T) {
		// --- Setup for rotation ---
		// New key and token
		privateKey2, _ := rsa.GenerateKey(rand.Reader, 2048)
		jwk2 := jose.JSONWebKey{Key: &privateKey2.PublicKey, KeyID: "test-kid-2", Algorithm: "RS256"}
		token2 := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "test2"})
		token2.Header["kid"] = "test-kid-2"
		tokenString2, _ := token2.SignedString(privateKey2)

		// Update the JWKS and ETag on the mock server
		mu.Lock()
		jwks.Keys = append(jwks.Keys, jwk2)
		etag = `"etag-2"`
		mu.Unlock()
		// --- End Setup ---

		// Verification should now trigger a fetch, get the new JWKS, and succeed
		_, err := refresher.Verify(context.Background(), tokenString2)
		assert.NoError(t, err)
	})
}
