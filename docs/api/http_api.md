# HTTP API Documentation

This document describes the HTTP API for the `cbc-auth` service.

## Authentication

All protected endpoints require a `Bearer` token in the `Authorization` header.

```
Authorization: Bearer <your-access-token>
```

## Endpoints

### Authentication

#### `POST /api/v1/auth/token`

Issues a new pair of access and refresh tokens.

**Request Body:**

```json
{
  "grant_type": "client_credentials",
  "tenant_id": "your-tenant-id",
  "device_id": "your-device-id"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "access_token": "...",
    "refresh_token": "...",
    "access_token_expires_in": 3600,
    "refresh_token_expires_in": 2592000,
    "token_type": "Bearer"
  }
}
```

---

#### `POST /api/v1/auth/refresh`

Refreshes an access token using a refresh token.

**Request Body:**

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "your-refresh-token"
}
```

**Success Response (200 OK):** (Same as `/token`)

---

#### `POST /api/v1/auth/revoke`

Revokes a token.

**Request Body:**

```json
{
  "token": "token-to-revoke"
}
```

**Success Response (200 OK):**

```json
{
  "success": true,
  "data": {
    "status": "ok"
  }
}
```

---

### Device Management

#### `POST /api/v1/devices`

Registers a new device.

**Request Body:**

```json
{
  "device_id": "unique-device-id",
  "tenant_id": "your-tenant-id",
  "device_type": "laptop",
  "os": "macOS",
  "app_version": "1.0.0"
}
```

**Success Response (201 Created):** (Returns the created device object)

---

<!--Personal.AI order the ending-->