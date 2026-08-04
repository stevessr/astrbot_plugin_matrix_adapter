"""Discover OAuth2 and OIDC endpoints from a homeserver."""

import aiohttp

from ...core import _log
from .metadata import _fetch_auth_metadata
from .oidc import _fetch_oidc_config
from .well_known import _discover_via_well_known


class MatrixOAuth2DiscoveryEndpointsMixin:
    async def _discover_oauth_endpoints(self) -> dict:
        try:
            _log("info", f"Discovering OAuth2 configuration from {self.homeserver}")

            timeout_cfg = aiohttp.ClientTimeout(
                total=self._get_oauth_http_timeout_seconds()
            )
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                auth_metadata = await _fetch_auth_metadata(session, self)
                if auth_metadata is not None:
                    return auth_metadata

                issuer, auth_config = await _discover_via_well_known(session, self)

                oidc_config = await _fetch_oidc_config(session, issuer, auth_config)
                oidc_config.setdefault("issuer", self.issuer)
                oidc_config.setdefault(
                    "account_management_uri", auth_config.get("account")
                )
                return self._apply_discovered_oauth_metadata(oidc_config)

        except Exception as e:
            error_msg = str(e)
            _log("error", f"❌ Failed to discover OAuth2 configuration: {error_msg}")

            if "404" in error_msg or "not supported" in error_msg.lower():
                _log(
                    "error",
                    "💡 This homeserver does not support OAuth2 authentication. "
                    "Please change matrix_auth_method to 'password' or 'token' in your configuration.",
                )
            else:
                _log(
                    "error",
                    "Please ensure your Matrix homeserver supports OAuth2/OIDC authentication. "
                    "Check the server's /_matrix/client/v1/auth_metadata or "
                    "/.well-known/matrix/client endpoint.",
                )
            raise
