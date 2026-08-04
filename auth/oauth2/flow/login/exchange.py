"""Authorization-code exchange for the OAuth2 login flow."""

from urllib.parse import urlencode

import aiohttp

from ...core import _log


async def _exchange_login_code(
    self, token_endpoint: str, code: str, pkce_verifier: str
) -> dict:
    """Exchange the authorization code for tokens and return the login result."""
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": self.redirect_uri,
        "client_id": self.client_id,
        "code_verifier": pkce_verifier,
    }

    if self.client_secret:
        token_data["client_secret"] = self.client_secret

    token_timeout_seconds = self._resolve_oauth_http_timeout_seconds(
        cap_seconds=self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS
    )
    token_timeout = aiohttp.ClientTimeout(total=token_timeout_seconds)
    async with aiohttp.ClientSession(timeout=token_timeout) as session:
        async with session.post(
            token_endpoint,
            data=urlencode(token_data),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as response:
            if response.status != 200:
                error_text = await response.text()
                raise Exception(f"Token exchange failed: {error_text}")

            token_response = await response.json()

    # Extract tokens
    self.access_token = token_response.get("access_token")
    self.refresh_token = token_response.get("refresh_token")
    self.token_type = token_response.get("token_type", "Bearer")
    self.expires_in = token_response.get("expires_in")

    # Set access token in client
    self.client.access_token = self.access_token

    # Get user info
    whoami = await self.client.whoami()
    self.device_id = whoami.get("device_id") or self.device_id

    _log("info", f"OAuth2 login successful: {whoami.get('user_id')}")

    return {
        "access_token": self.access_token,
        "refresh_token": self.refresh_token,
        "user_id": whoami.get("user_id"),
        "device_id": self.device_id,
        "token_type": self.token_type,
        "expires_in": self.expires_in,
    }
