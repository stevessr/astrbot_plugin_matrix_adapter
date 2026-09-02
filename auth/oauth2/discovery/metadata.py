"""Apply discovered OAuth2 metadata to a client."""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..core import _log

DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class MatrixOAuth2DiscoveryMetadataMixin:
    def _apply_discovered_oauth_metadata(self, metadata: dict) -> dict:
        issuer = metadata.get("issuer")
        authorization_endpoint = metadata.get("authorization_endpoint")
        token_endpoint = metadata.get("token_endpoint")
        revocation_endpoint = metadata.get("revocation_endpoint")
        registration_endpoint = metadata.get("registration_endpoint")
        device_authorization_endpoint = metadata.get("device_authorization_endpoint")
        grant_types_supported = metadata.get("grant_types_supported") or []
        account_management_uri = metadata.get("account_management_uri") or metadata.get(
            "account"
        )
        account_management_actions_supported = (
            metadata.get("account_management_actions_supported") or []
        )

        if not issuer or not authorization_endpoint or not token_endpoint:
            raise Exception("Missing required OAuth2 metadata fields")

        self.issuer = issuer
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.revocation_endpoint = revocation_endpoint
        self.registration_endpoint = registration_endpoint
        self.device_authorization_endpoint = device_authorization_endpoint
        self.grant_types_supported = [
            str(value)
            for value in grant_types_supported
            if isinstance(value, str) and value
        ]
        self.account_management_uri = account_management_uri
        self.account_management_actions_supported = [
            str(value)
            for value in account_management_actions_supported
            if isinstance(value, str) and value
        ]

        _log("info", "✅ OAuth2 discovery successful!")
        _log("info", f"  Authorization endpoint: {self.authorization_endpoint}")
        _log("info", f"  Token endpoint: {self.token_endpoint}")
        if self.registration_endpoint:
            _log("info", f"  Registration endpoint: {self.registration_endpoint}")
        if self.device_authorization_endpoint:
            _log(
                "info",
                f"  Device authorization endpoint: {self.device_authorization_endpoint}",
            )
        if self.account_management_uri:
            _log("info", f"  Account management URI: {self.account_management_uri}")

        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "revocation_endpoint": self.revocation_endpoint,
            "registration_endpoint": self.registration_endpoint,
            "device_authorization_endpoint": self.device_authorization_endpoint,
            "grant_types_supported": list(self.grant_types_supported),
            "account_management_uri": self.account_management_uri,
            "account_management_actions_supported": list(
                self.account_management_actions_supported
            ),
            # Compatibility with the pre-v1.18 discovery result used by this
            # adapter before account_management_uri was standardised.
            "account": self.account_management_uri,
        }

    def supports_device_authorization_grant(self) -> bool:
        """Return whether Matrix v1.18 / MSC4341 device auth can be used."""
        return bool(
            self.device_authorization_endpoint
            and DEVICE_CODE_GRANT_TYPE in self.grant_types_supported
        )

    def get_account_management_url(
        self,
        action: str | None = None,
        *,
        device_id: str | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> str | None:
        """Build a Matrix v1.18 / MSC4191 account-management deep link.

        If ``action`` is supplied and the server advertises a non-empty list of
        supported Matrix actions, unsupported actions are rejected rather than
        generating a link the server did not promise to understand.
        """
        if not self.account_management_uri:
            return None
        if action:
            advertised = self.account_management_actions_supported
            if advertised and action not in advertised:
                raise ValueError(
                    f"OAuth account-management action is not advertised: {action}"
                )

        parts = urlsplit(self.account_management_uri)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        if action:
            query["action"] = action
        if device_id:
            query["device_id"] = device_id
        if extra_params:
            query.update(
                {
                    str(key): str(value)
                    for key, value in extra_params.items()
                    if value is not None
                }
            )
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
        )
