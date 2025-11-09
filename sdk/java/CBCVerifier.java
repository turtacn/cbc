// CBCVerifier.java
package com.turtacn.cbc.sdk;

import java.util.Map;
import java.security.interfaces.RSAPublicKey;

public class CBCVerifier {

    private final String jwksUrl;
    private Map<String, RSAPublicKey> l1Cache;
    private String lastEtag;

    public CBCVerifier(String jwksUrl) {
        this.jwksUrl = jwksUrl;
    }

    /**
     * Fetches the JWKS from the configured URL, using ETag for caching.
     * This method should handle 304 Not Modified responses.
     */
    public void fetchJwks() {
        // TODO: Implement JWKS fetching with ETag
    }

    /**
     * Verifies a JWT string.
     *
     * This method should first attempt to verify the token using the cached JWKS.
     * If verification fails due to an unknown 'kid', it should trigger a
     * forced refresh of the JWKS and retry the verification once.
     *
     * @param tokenString The JWT to verify.
     * @return The verified token's claims.
     */
    public Map<String, Object> verify(String tokenString) {
        // TODO: Implement JWT verification with refresh-and-retry logic
        return null;
    }
}
