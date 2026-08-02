"""Discover OAuth2 and OIDC endpoints from a homeserver."""

import aiohttp

from ..core import _log


class MatrixOAuth2DiscoveryEndpointsMixin:
    async def _discover_oauth_endpoints(self) -> dict:
        try:
            _log("info", f"Discovering OAuth2 configuration from {self.homeserver}")

            timeout_cfg = aiohttp.ClientTimeout(
                total=self._get_oauth_http_timeout_seconds()
            )
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                auth_metadata_url = f"{self.homeserver}/_matrix/client/v1/auth_metadata"
                _log("debug", f"Fetching {auth_metadata_url}")

                try:
                    async with session.get(auth_metadata_url) as response:
                        if response.status == 200:
                            auth_metadata = await response.json()
                            _log("debug", f"Auth metadata: {auth_metadata}")
                            return self._apply_discovered_oauth_metadata(auth_metadata)
                        _log(
                            "debug",
                            "Direct auth metadata unavailable, falling back to "
                            f"/.well-known discovery (HTTP {response.status})",
                        )
                except Exception as e:
                    _log(
                        "warning",
                        "Direct auth metadata discovery failed, falling back to "
                        f"/.well-known discovery: {e}",
                    )

                well_known_url = f"{self.homeserver}/.well-known/matrix/client"
                _log("debug", f"Fetching {well_known_url}")

                async with session.get(
                    well_known_url, allow_redirects=True
                ) as response:
                    if response.status == 404:
                        raise Exception(
                            "Server does not have /.well-known/matrix/client endpoint. "
                            "OAuth2 authentication is not supported by this homeserver. "
                            "Please use 'password' or 'token' authentication instead."
                        )
                    elif response.status != 200:
                        raise Exception(
                            f"Failed to fetch well-known: HTTP {response.status}"
                        )

                    well_known_data = await response.json()
                    _log("debug", f"Well-known data: {well_known_data}")

                    auth_config = well_known_data.get("m.authentication", {})

                    if not auth_config:
                        auth_config = well_known_data.get(
                            "org.matrix.msc4143.authentication", {}
                        )

                    if not auth_config:
                        auth_config = well_known_data.get(
                            "org.matrix.msc2965.authentication", {}
                        )

                    if not auth_config:
                        _log(
                            "error",
                            "❌ Failed to discover OAuth2 configuration: No authentication configuration found in well-known.",
                        )
                        _log(
                            "error",
                            "💡 This homeserver does not support OAuth2 authentication.",
                        )
                        _log(
                            "error",
                            "💡 Please change matrix_auth_method to 'password' or 'token' in your configuration.",
                        )
                        _log(
                            "debug",
                            f"Available keys in well-known: {list(well_known_data.keys())}",
                        )
                        _log(
                            "debug",
                            "Authentication keys checked: m.authentication, org.matrix.msc4143.authentication, org.matrix.msc2965.authentication",
                        )
                        raise Exception(
                            "No authentication configuration found in well-known. "
                            "OAuth2 authentication is not supported by this homeserver. "
                            "Please use 'password' or 'token' authentication instead."
                        )

                    issuer = auth_config.get("issuer")
                    if not issuer:
                        raise Exception(
                            "No issuer found in m.authentication. "
                            "OAuth2 authentication is not properly configured on this homeserver. "
                            "Please use 'password' or 'token' authentication instead."
                        )

                    self.issuer = issuer
                    _log("info", f"Found OAuth2 issuer: {issuer}")

                    if not issuer.endswith("/"):
                        issuer = issuer + "/"

                    oidc_config_url = f"{issuer}.well-known/openid-configuration"
                    _log("debug", f"Fetching OIDC configuration from {oidc_config_url}")

                    async with session.get(oidc_config_url) as oidc_response:
                        if oidc_response.status != 200:
                            _log(
                                "error",
                                f"Failed to fetch OIDC configuration: HTTP {oidc_response.status}",
                            )
                            _log("error", f"URL requested: {oidc_config_url}")
                            try:
                                error_text = await oidc_response.text()
                                _log("error", f"Response body: {error_text[:200]}")
                            except Exception:
                                pass
                            raise Exception(
                                f"Failed to fetch OIDC configuration: HTTP {oidc_response.status}"
                            )

                        oidc_config = await oidc_response.json()
                        _log("debug", f"OIDC configuration: {oidc_config}")
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
