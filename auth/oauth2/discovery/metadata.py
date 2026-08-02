"""Apply discovered OAuth2 metadata to a client."""

from ..core import _log


class MatrixOAuth2DiscoveryMetadataMixin:
    def _apply_discovered_oauth_metadata(self, metadata: dict) -> dict:
        issuer = metadata.get("issuer")
        authorization_endpoint = metadata.get("authorization_endpoint")
        token_endpoint = metadata.get("token_endpoint")
        registration_endpoint = metadata.get("registration_endpoint")
        account_management_uri = metadata.get("account_management_uri") or metadata.get(
            "account"
        )

        if not issuer or not authorization_endpoint or not token_endpoint:
            raise Exception("Missing required OAuth2 metadata fields")

        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.registration_endpoint = registration_endpoint
        self.account_management_uri = account_management_uri

        _log("info", "✅ OAuth2 discovery successful!")
        _log("info", f"  Authorization endpoint: {self.authorization_endpoint}")
        _log("info", f"  Token endpoint: {self.token_endpoint}")
        if self.registration_endpoint:
            _log("info", f"  Registration endpoint: {self.registration_endpoint}")
        if self.account_management_uri:
            _log("info", f"  Account management URI: {self.account_management_uri}")

        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "registration_endpoint": self.registration_endpoint,
            "account": self.account_management_uri,
        }
