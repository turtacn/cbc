# gRPC API Documentation

This document describes the gRPC API for the `cbc-auth` service.

## Service: `AuthService`

### `rpc IssueToken(IssueTokenRequest) returns (TokenResponse)`

Issues a new token pair.

**Request:**

```protobuf
message IssueTokenRequest {
  string tenant_id = 1;
  string device_id = 2;
  string grant_type = 3;
}
```

**Response:**

```protobuf
message TokenResponse {
  string access_token = 1;
  string refresh_token = 2;
  int64 expires_in = 3;
}
```

**Example with `grpcurl`:**

```sh
grpcurl -plaintext -d '{"tenant_id": "...", "device_id": "..."}' localhost:50051 auth.AuthService/IssueToken
```

---

### `rpc RefreshToken(RefreshTokenRequest) returns (TokenResponse)`

Refreshes an access token.

**Request:**

```protobuf
message RefreshTokenRequest {
  string refresh_token = 1;
}
```

---

### `rpc VerifyToken(VerifyTokenRequest) returns (VerifyTokenResponse)`

Verifies a token.

**Request:**

```protobuf
message VerifyTokenRequest {
  string token = 1;
}
```

**Response:**

```protobuf
message VerifyTokenResponse {
  bool valid = 1;
  google.protobuf.Struct claims = 2;
}
```

<!--Personal.AI order the ending-->