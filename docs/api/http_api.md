# CBC Authentication Service - HTTP API Documentation

## Overview

This document describes the HTTP RESTful API endpoints provided by the CBC (CloudBrain-Cert) Authentication Service. All endpoints use HTTPS and return JSON responses.

**Base URL**: `https://auth.cloudbrain.cert/api/v1`

**Authentication**: Most endpoints require authentication via:
- Bearer Token (for agent/service authentication)
- mTLS (for MGR authentication)
- API Key (for admin operations)

**Content-Type**: `application/json` (unless otherwise specified)

---

## Table of Contents

1. [Authentication Endpoints](#authentication-endpoints)
   - [Issue Token](#post-apiv1authtoken)
   - [Refresh Token](#post-apiv1authrefresh)
   - [Revoke Token](#post-apiv1authrevoke)
   - [Get Public Keys (JWKS)](#get-apiv1authjwkstenant_id)
2. [Device Management Endpoints](#device-management-endpoints)
   - [Register Device](#post-apiv1devices)
   - [Get Device Info](#get-apiv1devicesdevice_id)
   - [Update Device](#put-apiv1devicesdevice_id)
3. [Health Check Endpoints](#health-check-endpoints)
   - [Liveness Probe](#get-healthlive)
   - [Readiness Probe](#get-healthready)
4. [Error Responses](#error-responses)

---

## Authentication Endpoints

### POST /api/v1/auth/token

Issue a new access token using a refresh token.

#### Request

**Headers**:
```http
Content-Type: application/x-www-form-urlencoded
````

**Body Parameters** (form-urlencoded):

| Parameter      | Type   | Required | Description                                   |
| -------------- | ------ | -------- | --------------------------------------------- |
| grant\_type    | string | Yes      | Must be `refresh_token`                       |
| refresh\_token | string | Yes      | Valid refresh token                           |
| scope          | string | No       | Requested scope (space-separated permissions) |

#### Response

**Success (200 OK)**:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAyIn0...",
  "scope": "agent:read agent:write intelligence:query"
}
```

**Response Fields**:

| Field          | Type   | Description                                           |
| -------------- | ------ | ----------------------------------------------------- |
| access\_token  | string | JWT access token (short-lived, 5-15 minutes)          |
| token\_type    | string | Always "Bearer"                                       |
| expires\_in    | int    | Token lifetime in seconds                             |
| refresh\_token | string | New refresh token (one-time use, invalidates old one) |
| scope          | string | Granted permissions                                   |

**Error Responses**:

* **400 Bad Request**: Invalid request format
* **401 Unauthorized**: Invalid or expired refresh token
* **429 Too Many Requests**: Rate limit exceeded

#### Example Request

```bash
curl -X POST https://auth.cloudbrain.cert/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0..."
```

#### Example Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0.eyJpc3MiOiJjYmMtYXV0aC1zZXJ2aWNlIiwic3ViIjoiYWdlbnQtNjc4OTAiLCJhdWQiOlsiaHR0cHM6Ly9pbnRlbGxpZ2VuY2Uuc2VydmljZSJdLCJleHAiOjE2OTgxMjQzNTYsIm5iZiI6MTY5ODEyMzQ1NiwiaWF0IjoxNjk4MTIzNDU2LCJqdGkiOiJ1bmlxdWUtdG9rZW4taWQtMDAyIiwidGVuYW50X2lkIjoidGVuYW50LTEyMzQ1Iiwic2NvcGUiOiJhZ2VudDpyZWFkIGFnZW50OndyaXRlIGludGVsbGlnZW5jZTpxdWVyeSIsImRldmljZV90cnVzdF9sZXZlbCI6ImhpZ2giLCJhenAiOiJjYmMtYXV0aC1zZXJ2aWNlIn0.signature",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAyIn0...",
  "scope": "agent:read agent:write intelligence:query"
}
```

---

### POST /api/v1/auth/refresh

*Deprecated: Use `/api/v1/auth/token` with `grant_type=refresh_token` instead.*

---

### POST /api/v1/auth/revoke

Revoke a refresh token or access token.

#### Request

**Headers**:

```http
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer {admin_access_token}
```

**Body Parameters** (form-urlencoded):

| Parameter         | Type   | Required | Description                                  |
| ----------------- | ------ | -------- | -------------------------------------------- |
| token             | string | Yes      | Token to revoke (refresh or access token)    |
| token\_type\_hint | string | No       | `refresh_token` or `access_token` (optional) |

#### Response

**Success (200 OK)**:

```json
{
  "revoked": true,
  "jti": "unique-token-id-001",
  "revoked_at": "2024-10-23T10:30:00Z"
}
```

**Response Fields**:

| Field       | Type   | Description                      |
| ----------- | ------ | -------------------------------- |
| revoked     | bool   | Always true on success           |
| jti         | string | JWT ID of the revoked token      |
| revoked\_at | string | ISO 8601 timestamp of revocation |

**Error Responses**:

* **400 Bad Request**: Missing or invalid token
* **401 Unauthorized**: Invalid admin credentials
* **404 Not Found**: Token not found or already revoked

#### Example Request

```bash
curl -X POST https://auth.cloudbrain.cert/api/v1/auth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d "token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0..." \
  -d "token_type_hint=refresh_token"
```

#### Example Response

```json
{
  "revoked": true,
  "jti": "a3f5c8d2-9b4e-4f1a-8d3c-7e2f4a9b1c5d",
  "revoked_at": "2024-10-24T14:25:36Z"
}
```

---

### GET /api/v1/auth/jwks/{tenant\_id}

Retrieve the JSON Web Key Set (JWKS) for a specific tenant. This endpoint is used by resource servers to verify JWT signatures locally.

#### Request

**Path Parameters**:

| Parameter  | Type   | Required | Description       |
| ---------- | ------ | -------- | ----------------- |
| tenant\_id | string | Yes      | Tenant identifier |

**Query Parameters**:

| Parameter | Type   | Required | Description                 |
| --------- | ------ | -------- | --------------------------- |
| kid       | string | No       | Specific key ID to retrieve |

#### Response

**Success (200 OK)**:

```json
{
  "tenant_id": "tenant-12345",
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "tenant-key-001",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB",
      "x5c": [
        "MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQEBBQUAMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTAeFw0xNjExMjIyMjIyMDVaFw0zMDA4MDEyMjIyMDVaMCMxITAfBgNVBAMTGGN1c3RvbWVyLWRlbW9zLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMCoW..."
      ],
      "x5t": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg",
      "x5t#S256": "NjVBRjY5MDlCMUIwNzU4RTA2QzZFMDQ4QzQ2MDAyQjVDNjk1RTM2Qg"
    }
  ]
}
```

**Response Fields**:

| Field      | Type   | Description                         |
| ---------- | ------ | ----------------------------------- |
| tenant\_id | string | Tenant identifier                   |
| keys       | array  | Array of JWK (JSON Web Key) objects |

**JWK Object Fields**:

| Field | Type   | Description                                   |
| ----- | ------ | --------------------------------------------- |
| kty   | string | Key type (RSA)                                |
| use   | string | Public key use (sig for signature)            |
| alg   | string | Algorithm (RS256, RS384, RS512)               |
| kid   | string | Key ID                                        |
| n     | string | RSA modulus (base64url-encoded)               |
| e     | string | RSA exponent (base64url-encoded)              |
| x5c   | array  | X.509 certificate chain (optional)            |
| x5t   | string | X.509 certificate SHA-1 thumbprint (optional) |

**Error Responses**:

* **404 Not Found**: Tenant not found or has no active keys
* **500 Internal Server Error**: Failed to retrieve keys from Vault

#### Example Request

```bash
curl -X GET https://auth.cloudbrain.cert/api/v1/auth/jwks/tenant-12345
```

#### Example Response

```json
{
  "tenant_id": "tenant-12345",
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "tenant-key-001",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
      "e": "AQAB"
    }
  ]
}
```

---

## Device Management Endpoints

### POST /api/v1/devices

Register a new device and issue a refresh token. This endpoint is typically called by MGR (Manager) services on behalf of agents.

#### Request

**Headers**:

```http
Content-Type: application/x-www-form-urlencoded
```

**Body Parameters** (form-urlencoded):

| Parameter               | Type   | Required | Description                                                     |
| ----------------------- | ------ | -------- | --------------------------------------------------------------- |
| client\_id              | string | Yes      | MGR client identifier                                           |
| client\_assertion\_type | string | Yes      | Fixed: `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| client\_assertion       | string | Yes      | MGR JWT assertion signed with private key                       |
| grant\_type             | string | Yes      | Fixed: `client_credentials`                                     |
| tenant\_id              | string | Yes      | Tenant identifier                                               |
| agent\_id               | string | Yes      | Agent unique identifier                                         |
| device\_fingerprint     | string | No       | Device fingerprint hash (recommended)                           |
| device\_metadata        | string | No       | JSON-encoded device metadata (OS, version, etc.)                |

#### Response

**Success (200 OK)**:

```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0...",
  "token_type": "Bearer",
  "expires_in": 7776000,
  "scope": "agent:read agent:write",
  "device_id": "device-abc123",
  "registered_at": "2024-10-24T14:30:00Z"
}
```

**Response Fields**:

| Field          | Type   | Description                           |
| -------------- | ------ | ------------------------------------- |
| refresh\_token | string | Long-lived refresh token (30-90 days) |
| token\_type    | string | Always "Bearer"                       |
| expires\_in    | int    | Refresh token lifetime in seconds     |
| scope          | string | Granted permissions                   |
| device\_id     | string | Internal device identifier            |
| registered\_at | string | ISO 8601 registration timestamp       |

**Error Responses**:

* **400 Bad Request**: Invalid request parameters
* **401 Unauthorized**: Invalid MGR client assertion
* **409 Conflict**: Device already registered with different fingerprint
* **429 Too Many Requests**: MGR rate limit exceeded

#### Example Request

```bash
curl -X POST https://auth.cloudbrain.cert/api/v1/devices \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=mgr-client-12345" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im1nci1rZXktMDAxIn0..." \
  -d "grant_type=client_credentials" \
  -d "tenant_id=tenant-12345" \
  -d "agent_id=agent-67890" \
  -d "device_fingerprint=sha256:a3f5c8d2..." \
  -d 'device_metadata={"os":"Linux","version":"5.15.0","arch":"x86_64"}'
```

#### Example Response

```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlbmFudC1rZXktMDAxIn0.eyJpc3MiOiJjYmMtYXV0aC1zZXJ2aWNlIiwic3ViIjoiYWdlbnQtNjc4OTAiLCJhdWQiOlsiaHR0cHM6Ly9hdXRoLmNsb3VkYnJhaW4uY2VydC9hcGkvdjEvYXV0aCJdLCJleHAiOjE3MDU5OTk0NTYsIm5iZiI6MTY5ODEyMzQ1NiwiaWF0IjoxNjk4MTIzNDU2LCJqdGkiOiJ1bmlxdWUtcmVmcmVzaC10b2tlbi0wMDEiLCJ0ZW5hbnRfaWQiOiJ0ZW5hbnQtMTIzNDUiLCJzY29wZSI6ImFnZW50OnJlYWQgYWdlbnQ6d3JpdGUiLCJ0eXBlIjoicmVmcmVzaF90b2tlbiJ9.signature",
  "token_type": "Bearer",
  "expires_in": 7776000,
  "scope": "agent:read agent:write",
  "device_id": "device-f7b3e9c1-4d2a-5f8e-9c1b-3a7d5e2f4b8c",
  "registered_at": "2024-10-24T14:30:45Z"
}
```

---

### GET /api/v1/devices/{device\_id}

Retrieve device information.

#### Request

**Headers**:

```http
Authorization: Bearer {access_token}
```

**Path Parameters**:

| Parameter  | Type   | Required | Description       |
| ---------- | ------ | -------- | ----------------- |
| device\_id | string | Yes      | Device identifier |

#### Response

**Success (200 OK)**:

```json
{
  "device_id": "device-f7b3e9c1-4d2a-5f8e-9c1b-3a7d5e2f4b8c",
  "agent_id": "agent-67890",
  "tenant_id": "tenant-12345",
  "device_fingerprint": "sha256:a3f5c8d2...",
  "trust_level": "high",
  "status": "active",
  "metadata": {
    "os": "Linux",
    "version": "5.15.0",
    "arch": "x86_64"
  },
  "registered_at": "2024-10-24T14:30:45Z",
  "last_seen_at": "2024-10-24T16:45:12Z"
}
```

**Error Responses**:

* **401 Unauthorized**: Invalid or missing access token
* **403 Forbidden**: Access denied (insufficient permissions)
* **404 Not Found**: Device not found

#### Example Request

```bash
curl -X GET https://auth.cloudbrain.cert/api/v1/devices/device-f7b3e9c1-4d2a-5f8e-9c1b-3a7d5e2f4b8c \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

### PUT /api/v1/devices/{device\_id}

Update device information.

#### Request

**Headers**:

```http
Content-Type: application/json
Authorization: Bearer {access_token}
```

**Path Parameters**:

| Parameter  | Type   | Required | Description       |
| ---------- | ------ | -------- | ----------------- |
| device\_id | string | Yes      | Device identifier |

**Body** (JSON):

```json
{
  "device_fingerprint": "sha256:b4e6d9f3...",
  "trust_level": "medium",
  "metadata": {
    "os": "Linux",
    "version": "5.16.0",
    "arch": "x86_64"
  }
}
```

#### Response

**Success (200 OK)**:

```json
{
  "device_id": "device-f7b3e9c1-4d2a-5f8e-9c1b-3a7d5e2f4b8c",
  "updated_at": "2024-10-24T17:00:00Z"
}
```

**Error Responses**:

* **400 Bad Request**: Invalid update parameters
* **401 Unauthorized**: Invalid or missing access token
* **403 Forbidden**: Access denied
* **404 Not Found**: Device not found

---

## Health Check Endpoints

### GET /health/live

Kubernetes liveness probe endpoint. Returns 200 if the service process is running.

#### Response

**Success (200 OK)**:

```json
{
  "status": "UP",
  "timestamp": "2024-10-24T17:15:30Z"
}
```

---

### GET /health/ready

Kubernetes readiness probe endpoint. Returns 200 if the service is ready to accept traffic.

#### Response

**Success (200 OK)**:

```json
{
  "status": "UP",
  "checks": {
    "database": "UP",
    "redis": "UP",
    "vault": "UP"
  },
  "timestamp": "2024-10-24T17:15:30Z"
}
```

**Service Unavailable (503)**:

```json
{
  "status": "DOWN",
  "checks": {
    "database": "UP",
    "redis": "DOWN",
    "vault": "UP"
  },
  "timestamp": "2024-10-24T17:15:30Z"
}
```

---

## Error Responses

All error responses follow the OAuth 2.0 error format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error description",
  "error_uri": "https://docs.cloudbrain.cert/errors#error_code"
}
```

### Standard Error Codes

| Error Code               | HTTP Status | Description                               |
| ------------------------ | ----------- | ----------------------------------------- |
| invalid\_request         | 400         | Missing or invalid request parameters     |
| invalid\_client          | 401         | Invalid client credentials or assertion   |
| invalid\_grant           | 401         | Invalid or expired token                  |
| unauthorized\_client     | 401         | Client not authorized for this operation  |
| unsupported\_grant\_type | 400         | Grant type not supported                  |
| invalid\_scope           | 400         | Requested scope is invalid or unavailable |
| server\_error            | 500         | Internal server error                     |
| temporarily\_unavailable | 503         | Service temporarily unavailable           |
| rate\_limit\_exceeded    | 429         | Too many requests                         |

### Rate Limit Headers

When rate limiting is applied, the following headers are included in responses:

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1698127200
Retry-After: 60
```

| Header                | Description                                    |
| --------------------- | ---------------------------------------------- |
| X-RateLimit-Limit     | Maximum requests allowed in the current window |
| X-RateLimit-Remaining | Remaining requests in the current window       |
| X-RateLimit-Reset     | Unix timestamp when the window resets          |
| Retry-After           | Seconds to wait before retrying (429 response) |

---

## Versioning

The API uses URI versioning (`/api/v1/...`). Breaking changes will result in a new version (`/api/v2/...`).

**Current Version**: v1
**Stability**: Production-ready
**Deprecation Policy**: Versions are supported for at least 12 months after a new version is released.

---

## Rate Limiting

Rate limits are enforced at three levels:

1. **Global**: 1,000,000 requests/second across all tenants
2. **Per-Tenant**: 100,000 requests/second per tenant
3. **Per-Agent**: 10 requests/minute for token refresh

Exceeding limits results in HTTP 429 with `Retry-After` header.

---

## Security Considerations

* **TLS 1.3** required for all connections
* **mTLS** recommended for MGR client authentication
* **JWT tokens** should be transmitted only over HTTPS
* **Refresh tokens** must be stored securely (encrypted at rest)
* **Access tokens** should be stored in memory only (not persisted)

---

## Support

For API support, please contact:

* **Email**: [api-support@cloudbrain.cert](mailto:api-support@cloudbrain.cert)
* **Documentation**: [https://docs.cloudbrain.cert](https://docs.cloudbrain.cert)
* **Issue Tracker**: [https://github.com/turtacn/cbc/issues](https://github.com/turtacn/cbc/issues)

---

**API Version**: 1.0.0
**Last Updated**: 2024-10-24
**Maintainer**: CBC Platform Team

<!--Personal.AI order the ending-->

