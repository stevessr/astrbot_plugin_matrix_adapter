"""
OAuth2 discovery and client registration.
"""

import aiohttp

from .oauth2_core import _log


class MatrixOAuth2Discovery:
    """Mixin for OAuth2 discovery and registration."""

    async def _discover_oauth_endpoints(self) -> dict:
        try:
            _log("info", f"Discovering OAuth2 configuration from {self.homeserver}")

            async with aiohttp.ClientSession() as session:
                well_known_url = f"{self.homeserver}/.well-known/matrix/client"
                _log("debug", f"Fetching {well_known_url}")

                async with session.get(well_known_url) as response:
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

                    account = auth_config.get("account")
                    if account:
                        self.account_management_uri = account
                        _log("info", f"Account management URI: {account}")

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

                        self.authorization_endpoint = oidc_config.get(
                            "authorization_endpoint"
                        )
                        self.token_endpoint = oidc_config.get("token_endpoint")
                        self.registration_endpoint = oidc_config.get(
                            "registration_endpoint"
                        )

                        if not self.authorization_endpoint or not self.token_endpoint:
                            raise Exception(
                                "Missing required endpoints in OIDC configuration"
                            )

                        _log("info", "✅ OAuth2 discovery successful!")
                        _log(
                            "info",
                            f"  Authorization endpoint: {self.authorization_endpoint}",
                        )
                        _log("info", f"  Token endpoint: {self.token_endpoint}")
                        if self.registration_endpoint:
                            _log(
                                "info",
                                f"  Registration endpoint: {self.registration_endpoint}",
                            )

                        return {
                            "issuer": self.issuer,
                            "authorization_endpoint": self.authorization_endpoint,
                            "token_endpoint": self.token_endpoint,
                            "registration_endpoint": self.registration_endpoint,
                            "account": self.account_management_uri,
                        }

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
                    "Check the server's /.well-known/matrix/client endpoint.",
                )
            raise

    async def _register_client(self, redirect_uri: str) -> dict[str, str]:
        if not self.registration_endpoint:
            raise Exception(
                "Dynamic client registration not supported by this server. "
                "Please provide a client_id manually."
            )

        try:
            _log("info", f"Registering OAuth2 client with {self.registration_endpoint}")

            registration_data = {
                "client_name": "AstrBot Matrix Client",
                "client_uri": "https://github.com/Soulter/AstrBot",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
                "application_type": "native",
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.registration_endpoint,
                    json=registration_data,
                    headers={"Content-Type": "application/json"},
                ) as response:
                    if response.status not in [200, 201]:
                        error_text = await response.text()
                        raise Exception(
                            f"Client registration failed: HTTP {response.status} - {error_text}"
                        )

                    registration_response = await response.json()

                    client_id = registration_response.get("client_id")
                    client_secret = registration_response.get("client_secret")

                    if not client_id:
                        raise Exception("No client_id in registration response")

                    _log("info", f"✅ Successfully registered client: {client_id}")

                    return {
                        "client_id": client_id,
                        "client_secret": client_secret,
                    }

        except Exception as e:
            _log("error", f"❌ Failed to register OAuth2 client: {e}")
            raise
