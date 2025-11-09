# Client SDK Integration Guide

This guide provides instructions for integrating and using the CBC Verifier SDKs to validate JWTs issued by the CBC Authentication Service.

## Overview

The CBC Verifier SDKs are designed to provide a seamless and robust way to handle JWT verification, including automatic management of JSON Web Key Sets (JWKS) and transparent handling of key rotation.

## Features

- **L1 Caching:** The SDKs maintain a local in-memory cache of the JWKS to avoid unnecessary network requests.
- **ETag Support:** The SDKs use HTTP ETag headers to efficiently update the JWKS cache. If the JWKS has not changed, the server will respond with a `304 Not Modified` status, saving bandwidth and reducing latency.
- **Automatic Key Rotation Handling:** When a JWT is encountered with a `kid` (Key ID) that is not in the local cache, the SDK will automatically attempt to refresh the JWKS from the server. This ensures that key rotation events are handled transparently without requiring manual intervention.

## Go SDK Usage

### Installation

```bash
go get github.com/turtacn/cbc/sdk/go/cbc_verifier
```

### Example

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/turtacn/cbc/sdk/go/cbc_verifier"
)

func main() {
	// The URL to your JWKS endpoint
	jwksURL := "http://localhost:8080/api/v1/auth/jwks/your_tenant_id"

	// Create a new verifier
	verifier := cbc_verifier.NewJWKS_Refresher(jwksURL)

	// Your JWT string
	tokenString := "your.jwt.string"

	// Verify the token
	token, err := verifier.Verify(context.Background(), tokenString)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	if token.Valid {
		fmt.Println("Token is valid!")
		// You can now access the claims from the token
		// claims := token.Claims.(jwt.MapClaims)
	} else {
		fmt.Println("Token is not valid.")
	}
}
```

## Key Rotation and Compromise

### Key Rotation

The CBC Authentication Service rotates keys by marking old keys as `deprecated` and issuing new keys as `active`. For a configured window of time, both `deprecated` and `active` keys are published in the JWKS endpoint.

The SDK is designed to handle this automatically. If a token is signed with a new key that is not yet in the SDK's cache, the verification will fail, triggering an automatic refresh of the JWKS. The SDK will then retry the verification with the updated key set.

### Key Compromise

In the event of a key compromise, the compromised key is immediately removed from the JWKS endpoint. The SDK's cache will be updated on the next refresh, which will be triggered either by the `Cache-Control` header's `max-age` expiring, or by an encounter with a token signed by a new (post-compromise) key.
