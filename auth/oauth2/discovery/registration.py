"""Register OAuth2 clients dynamically."""

import aiohttp

from ..core import _log


class MatrixOAuth2DiscoveryRegistrationMixin:
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

            timeout_cfg = aiohttp.ClientTimeout(
                total=self._get_oauth_http_timeout_seconds()
            )
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
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
