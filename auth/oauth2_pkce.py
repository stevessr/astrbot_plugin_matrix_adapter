"""
OAuth2 PKCE helpers.
"""

import base64
import hashlib
import secrets


class MatrixOAuth2PKCE:
    """Mixin for PKCE helpers."""

    def _generate_state(self) -> str:
        return secrets.token_urlsafe(32)

    def _generate_pkce_verifier(self) -> str:
        return secrets.token_urlsafe(64)

    def _generate_pkce_challenge(self, verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return challenge
