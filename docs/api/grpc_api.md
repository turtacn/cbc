# CBC Authentication Service - gRPC API Documentation

## Overview

This document describes the gRPC API provided by the CBC (CloudBrain-Cert) Authentication Service. The gRPC API is designed for high-performance, low-latency communication between internal services.

**Service Address**: `grpc://auth.cloudbrain.cert:9090`  
**TLS/mTLS**: Required for production environments  
**Protocol**: gRPC over HTTP/2  
**Serialization**: Protocol Buffers (proto3)

---

## Table of Contents

1. [Service Definition](#service-definition)
2. [Authentication Methods](#authentication-methods)
   - [IssueToken](#issuetoken)
   - [RefreshToken](#refreshtoken)
   - [RevokeToken](#revoketoken)
   - [ValidateToken](#validatetoken)
   - [IntrospectToken](#introspecttoken)
3. [Device Management Methods](#device-management-methods)
   - [RegisterDevice](#registerdevice)
   - [GetDevice](#getdevice)
   - [UpdateDevice](#updatedevice)
   - [ListDevices](#listdevices)
4. [Key Management Methods](#key-management-methods)
   - [GetPublicKeys](#getpublickeys)
   - [RotateKeys](#rotatekeys)
5. [Health Check Methods](#health-check-methods)
   - [Check](#check)
   - [Watch](#watch)
6. [Message Definitions](#message-definitions)
7. [Error Handling](#error-handling)
8. [Examples](#examples)

---

## Service Definition

### Proto File Location

```

protos/auth/v1/auth\_service.proto

````

### Service Interface

```protobuf
syntax = "proto3";

package auth.v1;

option go_package = "github.com/turtacn/cbc/internal/auth/pb;authpb";

import "google/protobuf/timestamp.proto";
import "google/protobuf/duration.proto";
import "google/protobuf/empty.proto";

// AuthService provides authentication and authorization operations
service AuthService {
  // Issue a new access token using a refresh token
  rpc IssueToken(IssueTokenRequest) returns (IssueTokenResponse);
  
  // Refresh an access token (deprecated, use IssueToken instead)
  rpc RefreshToken(RefreshTokenRequest) returns (RefreshTokenResponse);
  
  // Revoke a token (refresh or access token)
  rpc RevokeToken(RevokeTokenRequest) returns (RevokeTokenResponse);
  
  // Validate a token and return claims (lightweight)
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);
  
  // Introspect a token and return full metadata
  rpc IntrospectToken(IntrospectTokenRequest) returns (IntrospectTokenResponse);
  
  // Register a new device and issue a refresh token
  rpc RegisterDevice(RegisterDeviceRequest) returns (RegisterDeviceResponse);
  
  // Get device information
  rpc GetDevice(GetDeviceRequest) returns (GetDeviceResponse);
  
  // Update device information
  rpc UpdateDevice(UpdateDeviceRequest) returns (UpdateDeviceResponse);
  
  // List devices for a tenant/agent
  rpc ListDevices(ListDevicesRequest) returns (ListDevicesResponse);
  
  // Get public keys (JWKS) for token verification
  rpc GetPublicKeys(GetPublicKeysRequest) returns (GetPublicKeysResponse);
  
  // Rotate tenant signing keys
  rpc RotateKeys(RotateKeysRequest) returns (RotateKeysResponse);
}

// HealthService provides health check operations (gRPC health checking protocol)
service HealthService {
  // Check health status
  rpc Check(HealthCheckRequest) returns (HealthCheckResponse);
  
  // Watch health status (streaming)
  rpc Watch(HealthCheckRequest) returns (stream HealthCheckResponse);
}
````

---

## Authentication Methods

### IssueToken

Issue a new access token using a valid refresh token. This is the recommended method for token refresh.

#### Request

```protobuf
message IssueTokenRequest {
  // Grant type (must be "refresh_token")
  string grant_type = 1;
  
  // Valid refresh token
  string refresh_token = 2;
  
  // Optional: Requested scope (space-separated permissions)
  string scope = 3;
  
  // Optional: Tenant ID (can be derived from refresh token)
  string tenant_id = 4;
}
```

#### Response

```protobuf
message IssueTokenResponse {
  // JWT access token
  string access_token = 1;
  
  // Token type (always "Bearer")
  string token_type = 2;
  
  // Token lifetime in seconds
  int64 expires_in = 3;
  
  // New refresh token (one-time use)
  string refresh_token = 4;
  
  // Granted scope
  string scope = 5;
  
  // Token issuance timestamp
  google.protobuf.Timestamp issued_at = 6;
}
```

#### Example (Go)

```go
package main

import (
    "context"
    "log"
    "time"
    
    authpb "github.com/turtacn/cbc/internal/auth/pb"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

func main() {
    conn, err := grpc.Dial("auth.cloudbrain.cert:9090", 
        grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    client := authpb.NewAuthServiceClient(conn)
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    resp, err := client.IssueToken(ctx, &authpb.IssueTokenRequest{
        GrantType:    "refresh_token",
        RefreshToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        Scope:        "agent:read agent:write",
    })
    if err != nil {
        log.Fatalf("IssueToken failed: %v", err)
    }
    
    log.Printf("Access token: %s", resp.AccessToken)
    log.Printf("Expires in: %d seconds", resp.ExpiresIn)
}
```

---

### RefreshToken

*Deprecated: Use `IssueToken` instead.*

Refresh an access token using a refresh token.

#### Request

```protobuf
message RefreshTokenRequest {
  // Valid refresh token
  string refresh_token = 1;
  
  // Optional: Requested scope
  string scope = 2;
}
```

#### Response

```protobuf
message RefreshTokenResponse {
  // JWT access token
  string access_token = 1;
  
  // Token type
  string token_type = 2;
  
  // Token lifetime in seconds
  int64 expires_in = 3;
  
  // New refresh token
  string refresh_token = 4;
  
  // Granted scope
  string scope = 5;
}
```

---

### RevokeToken

Revoke a token (refresh or access token), adding it to the blacklist.

#### Request

```protobuf
message RevokeTokenRequest {
  // Token to revoke
  string token = 1;
  
  // Optional: Token type hint ("refresh_token" or "access_token")
  string token_type_hint = 2;
  
  // Optional: Reason for revocation
  string reason = 3;
}
```

#### Response

```protobuf
message RevokeTokenResponse {
  // Whether the token was successfully revoked
  bool revoked = 1;
  
  // JWT ID (jti) of the revoked token
  string jti = 2;
  
  // Revocation timestamp
  google.protobuf.Timestamp revoked_at = 3;
}
```

#### Example (Go)

```go
resp, err := client.RevokeToken(ctx, &authpb.RevokeTokenRequest{
    Token:         "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    TokenTypeHint: "refresh_token",
    Reason:        "User logged out",
})
if err != nil {
    log.Fatalf("RevokeToken failed: %v", err)
}

log.Printf("Token revoked: %v (jti: %s)", resp.Revoked, resp.Jti)
```

---

### ValidateToken

Validate a token and return basic claims. This is a lightweight operation for quick validation.

#### Request

```protobuf
message ValidateTokenRequest {
  // Token to validate
  string token = 1;
  
  // Optional: Expected audience
  repeated string audience = 2;
  
  // Optional: Expected scope
  string scope = 3;
}
```

#### Response

```protobuf
message ValidateTokenResponse {
  // Whether the token is valid
  bool valid = 1;
  
  // Token subject (agent ID, user ID, etc.)
  string subject = 2;
  
  // Tenant ID
  string tenant_id = 3;
  
  // Token scope
  string scope = 4;
  
  // Token expiration time
  google.protobuf.Timestamp expires_at = 5;
  
  // Validation error (if valid = false)
  string error = 6;
}
```

#### Example (Go)

```go
resp, err := client.ValidateToken(ctx, &authpb.ValidateTokenRequest{
    Token:    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    Audience: []string{"https://intelligence.service"},
    Scope:    "intelligence:query",
})
if err != nil {
    log.Fatalf("ValidateToken failed: %v", err)
}

if resp.Valid {
    log.Printf("Token valid for subject: %s", resp.Subject)
} else {
    log.Printf("Token invalid: %s", resp.Error)
}
```

---

### IntrospectToken

Introspect a token and return full metadata. This is a more expensive operation than validation.

#### Request

```protobuf
message IntrospectTokenRequest {
  // Token to introspect
  string token = 1;
  
  // Optional: Token type hint
  string token_type_hint = 2;
}
```

#### Response

```protobuf
message IntrospectTokenResponse {
  // Whether the token is active
  bool active = 1;
  
  // Token scope
  string scope = 2;
  
  // Client ID
  string client_id = 3;
  
  // Username/subject
  string username = 4;
  
  // Token type
  string token_type = 5;
  
  // Expiration time (Unix timestamp)
  int64 exp = 6;
  
  // Issued at time (Unix timestamp)
  int64 iat = 7;
  
  // Not before time (Unix timestamp)
  int64 nbf = 8;
  
  // Subject
  string sub = 9;
  
  // Audience
  repeated string aud = 10;
  
  // Issuer
  string iss = 11;
  
  // JWT ID
  string jti = 12;
  
  // Tenant ID
  string tenant_id = 13;
  
  // Device trust level
  string device_trust_level = 14;
  
  // Custom claims (JSON-encoded)
  map<string, string> custom_claims = 15;
}
```

---

## Device Management Methods

### RegisterDevice

Register a new device and issue a refresh token. Typically called by MGR services.

#### Request

```protobuf
message RegisterDeviceRequest {
  // MGR client ID
  string client_id = 1;
  
  // MGR JWT assertion (signed with MGR private key)
  string client_assertion = 2;
  
  // Assertion type (fixed: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
  string client_assertion_type = 3;
  
  // Grant type (fixed: "client_credentials")
  string grant_type = 4;
  
  // Tenant ID
  string tenant_id = 5;
  
  // Agent ID
  string agent_id = 6;
  
  // Optional: Device fingerprint hash
  string device_fingerprint = 7;
  
  // Optional: Device metadata
  DeviceMetadata device_metadata = 8;
}

message DeviceMetadata {
  // Operating system
  string os = 1;
  
  // OS version
  string version = 2;
  
  // Architecture
  string arch = 3;
  
  // Hostname
  string hostname = 4;
  
  // IP address
  string ip_address = 5;
  
  // MAC address
  string mac_address = 6;
  
  // Custom metadata (JSON-encoded)
  map<string, string> custom = 7;
}
```

#### Response

```protobuf
message RegisterDeviceResponse {
  // Long-lived refresh token
  string refresh_token = 1;
  
  // Token type
  string token_type = 2;
  
  // Refresh token lifetime in seconds
  int64 expires_in = 3;
  
  // Granted scope
  string scope = 4;
  
  // Internal device ID
  string device_id = 5;
  
  // Registration timestamp
  google.protobuf.Timestamp registered_at = 6;
}
```

#### Example (Go)

```go
resp, err := client.RegisterDevice(ctx, &authpb.RegisterDeviceRequest{
    ClientId:             "mgr-client-12345",
    ClientAssertion:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    ClientAssertionType:  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    GrantType:            "client_credentials",
    TenantId:             "tenant-12345",
    AgentId:              "agent-67890",
    DeviceFingerprint:    "sha256:a3f5c8d2...",
    DeviceMetadata: &authpb.DeviceMetadata{
        Os:       "Linux",
        Version:  "5.15.0",
        Arch:     "x86_64",
        Hostname: "agent-node-01",
    },
})
if err != nil {
    log.Fatalf("RegisterDevice failed: %v", err)
}

log.Printf("Device registered: %s", resp.DeviceId)
log.Printf("Refresh token expires in: %d seconds", resp.ExpiresIn)
```

---

### GetDevice

Retrieve device information.

#### Request

```protobuf
message GetDeviceRequest {
  // Device ID
  string device_id = 1;
  
  // Optional: Tenant ID (for authorization)
  string tenant_id = 2;
}
```

#### Response

```protobuf
message GetDeviceResponse {
  // Device information
  Device device = 1;
}

message Device {
  // Device ID
  string device_id = 1;
  
  // Agent ID
  string agent_id = 2;
  
  // Tenant ID
  string tenant_id = 3;
  
  // Device fingerprint
  string device_fingerprint = 4;
  
  // Trust level ("high", "medium", "low")
  string trust_level = 5;
  
  // Status ("active", "suspended", "revoked")
  string status = 6;
  
  // Device metadata
  DeviceMetadata metadata = 7;
  
  // Registration timestamp
  google.protobuf.Timestamp registered_at = 8;
  
  // Last seen timestamp
  google.protobuf.Timestamp last_seen_at = 9;
  
  // Last updated timestamp
  google.protobuf.Timestamp updated_at = 10;
}
```

---

### UpdateDevice

Update device information.

#### Request

```protobuf
message UpdateDeviceRequest {
  // Device ID
  string device_id = 1;
  
  // Optional: New device fingerprint
  string device_fingerprint = 2;
  
  // Optional: New trust level
  string trust_level = 3;
  
  // Optional: New status
  string status = 4;
  
  // Optional: Updated metadata
  DeviceMetadata metadata = 5;
}
```

#### Response

```protobuf
message UpdateDeviceResponse {
  // Updated device information
  Device device = 1;
  
  // Update timestamp
  google.protobuf.Timestamp updated_at = 2;
}
```

---

### ListDevices

List devices for a tenant or agent.

#### Request

```protobuf
message ListDevicesRequest {
  // Optional: Tenant ID filter
  string tenant_id = 1;
  
  // Optional: Agent ID filter
  string agent_id = 2;
  
  // Optional: Status filter
  string status = 3;
  
  // Optional: Trust level filter
  string trust_level = 4;
  
  // Pagination: page size
  int32 page_size = 5;
  
  // Pagination: page token
  string page_token = 6;
}
```

#### Response

```protobuf
message ListDevicesResponse {
  // List of devices
  repeated Device devices = 1;
  
  // Next page token (empty if no more pages)
  string next_page_token = 2;
  
  // Total count (if available)
  int64 total_count = 3;
}
```

---

## Key Management Methods

### GetPublicKeys

Retrieve public keys (JWKS) for token verification.

#### Request

```protobuf
message GetPublicKeysRequest {
  // Tenant ID
  string tenant_id = 1;
  
  // Optional: Specific key ID
  string kid = 2;
}
```

#### Response

```protobuf
message GetPublicKeysResponse {
  // Tenant ID
  string tenant_id = 1;
  
  // List of public keys
  repeated JWK keys = 2;
}

message JWK {
  // Key type (e.g., "RSA")
  string kty = 1;
  
  // Public key use (e.g., "sig")
  string use = 2;
  
  // Algorithm (e.g., "RS256")
  string alg = 3;
  
  // Key ID
  string kid = 4;
  
  // RSA modulus (base64url-encoded)
  string n = 5;
  
  // RSA exponent (base64url-encoded)
  string e = 6;
  
  // Optional: X.509 certificate chain
  repeated string x5c = 7;
  
  // Optional: X.509 certificate SHA-1 thumbprint
  string x5t = 8;
  
  // Optional: X.509 certificate SHA-256 thumbprint
  string x5t_s256 = 9;
}
```

---

### RotateKeys

Rotate tenant signing keys.

#### Request

```protobuf
message RotateKeysRequest {
  // Tenant ID
  string tenant_id = 1;
  
  // Optional: Key algorithm (default: RS256)
  string algorithm = 2;
  
  // Optional: Key size in bits (default: 2048)
  int32 key_size = 3;
  
  // Optional: Grace period before old key is invalidated
  google.protobuf.Duration grace_period = 4;
}
```

#### Response

```protobuf
message RotateKeysResponse {
  // New key ID
  string new_kid = 1;
  
  // Old key ID
  string old_kid = 2;
  
  // Rotation timestamp
  google.protobuf.Timestamp rotated_at = 3;
  
  // Old key expiration time
  google.protobuf.Timestamp old_key_expires_at = 4;
}
```

---

## Health Check Methods

### Check

Check service health status (implements gRPC health checking protocol).

#### Request

```protobuf
message HealthCheckRequest {
  // Service name (empty for overall health)
  string service = 1;
}
```

#### Response

```protobuf
message HealthCheckResponse {
  enum ServingStatus {
    UNKNOWN = 0;
    SERVING = 1;
    NOT_SERVING = 2;
    SERVICE_UNKNOWN = 3;
  }
  
  // Serving status
  ServingStatus status = 1;
  
  // Optional: Health details
  map<string, string> details = 2;
}
```

---

### Watch

Watch service health status (streaming).

#### Request

```protobuf
message HealthCheckRequest {
  string service = 1;
}
```

#### Response (Stream)

```protobuf
stream HealthCheckResponse {
  ServingStatus status = 1;
  map<string, string> details = 2;
}
```

---

## Message Definitions

### Common Types

```protobuf
// Timestamp: google.protobuf.Timestamp
// Duration: google.protobuf.Duration
// Empty: google.protobuf.Empty

// Token types
enum TokenType {
  TOKEN_TYPE_UNSPECIFIED = 0;
  TOKEN_TYPE_ACCESS = 1;
  TOKEN_TYPE_REFRESH = 2;
}

// Grant types
enum GrantType {
  GRANT_TYPE_UNSPECIFIED = 0;
  GRANT_TYPE_REFRESH_TOKEN = 1;
  GRANT_TYPE_CLIENT_CREDENTIALS = 2;
}

// Device status
enum DeviceStatus {
  DEVICE_STATUS_UNSPECIFIED = 0;
  DEVICE_STATUS_ACTIVE = 1;
  DEVICE_STATUS_SUSPENDED = 2;
  DEVICE_STATUS_REVOKED = 3;
}

// Trust level
enum TrustLevel {
  TRUST_LEVEL_UNSPECIFIED = 0;
  TRUST_LEVEL_LOW = 1;
  TRUST_LEVEL_MEDIUM = 2;
  TRUST_LEVEL_HIGH = 3;
}
```

---

## Error Handling

### gRPC Status Codes

The service uses standard gRPC status codes:

| Code                    | Description                       |
| ----------------------- | --------------------------------- |
| OK (0)                  | Success                           |
| CANCELLED (1)           | Operation cancelled               |
| INVALID\_ARGUMENT (3)   | Invalid request parameters        |
| DEADLINE\_EXCEEDED (4)  | Request timeout                   |
| NOT\_FOUND (5)          | Resource not found                |
| ALREADY\_EXISTS (6)     | Resource already exists           |
| PERMISSION\_DENIED (7)  | Access denied                     |
| UNAUTHENTICATED (16)    | Authentication required or failed |
| RESOURCE\_EXHAUSTED (8) | Rate limit exceeded               |
| UNAVAILABLE (14)        | Service temporarily unavailable   |
| INTERNAL (13)           | Internal server error             |

### Error Details

Error details are returned in the status message and can include structured metadata:

```go
import (
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

// Example error with details
st := status.New(codes.InvalidArgument, "Invalid token format")
st, _ = st.WithDetails(&errdetails.BadRequest{
    FieldViolations: []*errdetails.BadRequest_FieldViolation{
        {
            Field:       "token",
            Description: "Token must be a valid JWT",
        },
    },
})
return st.Err()
```

---

## Examples

### Complete Go Client Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    authpb "github.com/turtacn/cbc/internal/auth/pb"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    // Load TLS credentials
    creds, err := credentials.NewClientTLSFromFile("ca-cert.pem", "")
    if err != nil {
        log.Fatalf("Failed to load TLS credentials: %v", err)
    }
    
    // Connect to gRPC server
    conn, err := grpc.Dial(
        "auth.cloudbrain.cert:9090",
        grpc.WithTransportCredentials(creds),
        grpc.WithBlock(),
    )
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()
    
    client := authpb.NewAuthServiceClient(conn)
    
    // Register device
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    regResp, err := client.RegisterDevice(ctx, &authpb.RegisterDeviceRequest{
        ClientId:            "mgr-client-12345",
        ClientAssertion:     "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
        ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        GrantType:           "client_credentials",
        TenantId:            "tenant-12345",
        AgentId:             "agent-67890",
        DeviceFingerprint:   "sha256:a3f5c8d2...",
        DeviceMetadata: &authpb.DeviceMetadata{
            Os:       "Linux",
            Version:  "5.15.0",
            Arch:     "x86_64",
            Hostname: "agent-node-01",
        },
    })
    if err != nil {
        log.Fatalf("RegisterDevice failed: %v", err)
    }
    
    fmt.Printf("Device registered: %s\n", regResp.DeviceId)
    refreshToken := regResp.RefreshToken
    
    // Issue access token
    tokenResp, err := client.IssueToken(ctx, &authpb.IssueTokenRequest{
        GrantType:    "refresh_token",
        RefreshToken: refreshToken,
        Scope:        "agent:read agent:write",
    })
    if err != nil {
        log.Fatalf("IssueToken failed: %v", err)
    }
    
    fmt.Printf("Access token issued (expires in %d seconds)\n", tokenResp.ExpiresIn)
    accessToken := tokenResp.AccessToken
    
    // Validate token
    validateResp, err := client.ValidateToken(ctx, &authpb.ValidateTokenRequest{
        Token:    accessToken,
        Audience: []string{"https://intelligence.service"},
    })
    if err != nil {
        log.Fatalf("ValidateToken failed: %v", err)
    }
    
    if validateResp.Valid {
        fmt.Printf("Token valid for subject: %s (tenant: %s)\n",
            validateResp.Subject, validateResp.TenantId)
    } else {
        fmt.Printf("Token invalid: %s\n", validateResp.Error)
    }
    
    // Revoke token
    revokeResp, err := client.RevokeToken(ctx, &authpb.RevokeTokenRequest{
        Token:         refreshToken,
        TokenTypeHint: "refresh_token",
        Reason:        "Test revocation",
    })
    if err != nil {
        log.Fatalf("RevokeToken failed: %v", err)
    }
    
    fmt.Printf("Token revoked: %v (jti: %s)\n", revokeResp.Revoked, revokeResp.Jti)
}
```

### Python Client Example

```python
import grpc
from auth.v1 import auth_service_pb2, auth_service_pb2_grpc

def main():
    # Load TLS credentials
    with open('ca-cert.pem', 'rb') as f:
        creds = grpc.ssl_channel_credentials(f.read())
    
    # Connect to gRPC server
    channel = grpc.secure_channel('auth.cloudbrain.cert:9090', creds)
    client = auth_service_pb2_grpc.AuthServiceStub(channel)
    
    # Issue token
    response = client.IssueToken(auth_service_pb2.IssueTokenRequest(
        grant_type='refresh_token',
        refresh_token='eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...',
        scope='agent:read agent:write'
    ))
    
    print(f'Access token: {response.access_token}')
    print(f'Expires in: {response.expires_in} seconds')

if __name__ == '__main__':
    main()
```

---

## Performance Considerations

* **Connection Pooling**: Reuse gRPC connections across requests
* **Timeouts**: Set appropriate context deadlines (5-10 seconds recommended)
* **Retries**: Implement exponential backoff for transient failures
* **Load Balancing**: Use client-side load balancing for high availability
* **Keepalive**: Configure keepalive pings for long-lived connections

---

## Security Best Practices

* **TLS/mTLS**: Always use TLS 1.3 in production
* **Token Storage**: Store refresh tokens encrypted at rest
* **Token Transmission**: Never log or expose tokens in plaintext
* **Validation**: Always validate tokens server-side before use
* **Revocation**: Implement token revocation checks for high-security operations

---

## Support

For gRPC API support, please contact:

* **Email**: [api-support@cloudbrain.cert](mailto:api-support@cloudbrain.cert)
* **Documentation**: [https://docs.cloudbrain.cert/grpc](https://docs.cloudbrain.cert/grpc)
* **Proto Files**: [https://github.com/turtacn/cbc/tree/main/protos](https://github.com/turtacn/cbc/tree/main/protos)

---

**API Version**: 1.0.0
**Last Updated**: 2024-10-24
**Maintainer**: CBC Platform Team

<!--Personal.AI order the ending-->


