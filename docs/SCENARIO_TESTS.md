# Scenario-Based E2E Tests

This document outlines the key end-to-end testing scenarios for the authentication service and maps them to their corresponding test implementations.

## 1. Core Authentication Lifecycle

This scenario tests the fundamental "happy path" of the token lifecycle.

**Steps:**
1.  A client requests a new token pair (access and refresh).
2.  The client uses the access token to access a protected resource (simulated).
3.  The client uses the refresh token to obtain a new token pair.
4.  The client verifies that the *old* refresh token is now invalid (rotated).
5.  The client revokes the new access token.
6.  The client verifies that the revoked access token is now invalid.

**Traceability:**
*   **Test File:** `tests/e2e/auth_e2e_test.go`
*   **Test Function:** `TestAuthLifecycle_E2E`

## 2. Health & Readiness Probes

This scenario ensures that the server's health and readiness endpoints are functioning correctly.

**Steps:**
1.  A client makes a GET request to `/health`.
2.  The server should respond with a 200 OK and a status of "ok".

**Traceability:**
*   **Test File:** (Not yet implemented, but covered by `serverlite` implementation)
*   **Handler:** `internal/serverlite/serverlite.go#healthCheck`

## 3. Error Scenarios

These scenarios test the server's behavior when presented with invalid input.

*   **Invalid Request Body:** The client sends a malformed JSON body to an endpoint.
*   **Invalid Token:** The client attempts to refresh with a malformed, expired, or tampered refresh token.
*   **Revoked Token:** The client attempts to use a token that has been explicitly revoked.

**Traceability:**
*   **Test File:** (To be implemented)
*   **Handlers:** `internal/serverlite/serverlite.go` (error handling paths)

## 4. Concurrency & Stability

This scenario tests the server's ability to handle multiple concurrent requests without race conditions or deadlocks.

**Steps:**
1.  Multiple clients concurrently attempt to refresh tokens.
2.  The server should correctly handle all requests, issuing new tokens and revoking old ones without error.

**Traceability:**
*   **Test File:** (To be implemented)

## 5. Build & Startup

This scenario ensures that the server can be built and started correctly.

**Steps:**
1.  The `go build` command is run on `cmd/server/main.go`.
2.  The resulting binary is executed.
3.  The server starts and listens on the configured port.

**Traceability:**
*   **CI Workflow:** `.github/workflows/test.yml`
*   **Entrypoint:** `cmd/server/main.go`
