"""OAuth2 refresh-token flow."""

from typing import Any
from urllib.parse import urlencode

import aiohttp

from ..core import _log


class MatrixOAuth2FlowRefreshMixin:
    async def refresh_access_token(self) -> dict[str, Any]:
        """
        Refresh access token using refresh token

        Returns:
            New token response

        Raises:
            Exception: If refresh fails
        """
        if not self.refresh_token:
            raise Exception("No refresh token available")

        try:
            endpoints = await self._discover_oauth_endpoints()
            token_endpoint = endpoints["token_endpoint"]

            token_data = {
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token,
                "client_id": self.client_id,
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
                        raise Exception(f"Token refresh failed: {error_text}")

                    token_response = await response.json()

            # Update tokens
            self.access_token = token_response.get("access_token")
            if "refresh_token" in token_response:
                self.refresh_token = token_response["refresh_token"]
            self.expires_in = token_response.get("expires_in")

            # Update client
            self.client.access_token = self.access_token

            _log("info", "Access token refreshed successfully")

            return token_response

        except Exception as e:
            _log("error", f"Failed to refresh access token: {e}")
            raise
