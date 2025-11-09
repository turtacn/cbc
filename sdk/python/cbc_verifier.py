# cbc_verifier.py

class CBCVerifier:
    def __init__(self, jwks_url):
        """
        Initializes the CBCVerifier.

        :param jwks_url: The URL to the JWKS endpoint.
        """
        self.jwks_url = jwks_url
        self.l1_cache = {}
        self.last_etag = None

    def fetch_jwks(self):
        """
        Fetches the JWKS from the configured URL, using ETag for caching.
        This method should handle 304 Not Modified responses.
        """
        # TODO: Implement JWKS fetching with ETag
        pass

    def verify(self, token_string):
        """
        Verifies a JWT string.

        This method should first attempt to verify the token using the cached JWKS.
        If verification fails due to an unknown 'kid', it should trigger a
        forced refresh of the JWKS and retry the verification once.

        :param token_string: The JWT to verify.
        :return: The verified token's claims.
        """
        # TODO: Implement JWT verification with refresh-and-retry logic
        pass
