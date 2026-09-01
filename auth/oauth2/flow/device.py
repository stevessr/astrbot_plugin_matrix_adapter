"""Matrix v1.18 OAuth Device Authorization Grant (MSC4341)."""

import asyncio
import inspect
import time
from urllib.parse import urlencode

import aiohttp

from ..core import _log
from ..discovery.metadata import DEVICE_CODE_GRANT_TYPE


class MatrixOAuth2DeviceGrantMixin:
    """Implement RFC 8628 device-code login for headless Matrix clients."""

    async def login_device(self, *, on_verification=None) -> dict:
        """Authenticate using Matrix v1.18 / MSC4341 device authorization.

        ``on_verification`` may be a sync or async callback receiving a dict with
        ``user_code``, ``verification_uri``, ``verification_uri_complete``,
        ``expires_in`` and ``interval``. AstrBot also logs these values so a
        fully headless deployment can complete the flow from its console.
        """
        endpoints = await self._discover_oauth_endpoints()
        if not self.supports_device_authorization_grant():
            raise RuntimeError(
                "Homeserver OAuth metadata does not advertise the Matrix v1.18 "
                "device authorization grant"
            )
        if not self.client_id:
            registration = await self._register_client(
                None,
                grant_types=[DEVICE_CODE_GRANT_TYPE, "refresh_token"],
            )
            self.client_id = registration["client_id"]
            self.client_secret = registration.get("client_secret")

        device_endpoint = self.device_authorization_endpoint
        token_endpoint = endpoints.get("token_endpoint") or self.token_endpoint
        if not device_endpoint or not token_endpoint:
            raise RuntimeError("Incomplete OAuth device authorization metadata")

        request_data = {
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
        }
        if self.client_secret:
            request_data["client_secret"] = self.client_secret

        timeout_seconds = self._resolve_oauth_http_timeout_seconds(
            cap_seconds=self._OAUTH2_HTTP_TIMEOUT_MAX_SECONDS
        )
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                device_endpoint,
                data=urlencode(request_data),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise RuntimeError(
                        f"Device authorization request failed: HTTP {response.status} - {error_text}"
                    )
                authorization = await response.json()

            device_code = authorization.get("device_code")
            user_code = authorization.get("user_code")
            verification_uri = authorization.get("verification_uri")
            verification_uri_complete = authorization.get("verification_uri_complete")
            if not device_code or not user_code or not verification_uri:
                raise RuntimeError(
                    "Device authorization response is missing device_code, user_code, or verification_uri"
                )

            try:
                expires_in = max(1, int(authorization.get("expires_in", 600)))
            except (TypeError, ValueError):
                expires_in = 600
            try:
                interval = max(1, int(authorization.get("interval", 5)))
            except (TypeError, ValueError):
                interval = 5

            verification = {
                "user_code": str(user_code),
                "verification_uri": str(verification_uri),
                "verification_uri_complete": (
                    str(verification_uri_complete)
                    if verification_uri_complete
                    else None
                ),
                "expires_in": expires_in,
                "interval": interval,
            }
            _log("info", "=" * 60)
            _log("info", "OAuth2 Device Authorization Required")
            _log("info", f"Open: {verification['verification_uri']}")
            _log("info", f"Code: {verification['user_code']}")
            if verification["verification_uri_complete"]:
                _log(
                    "info",
                    f"Direct verification URL: {verification['verification_uri_complete']}",
                )
            _log("info", "=" * 60)

            if on_verification is not None:
                callback_result = on_verification(dict(verification))
                if inspect.isawaitable(callback_result):
                    await callback_result

            deadline = time.monotonic() + expires_in
            poll_interval = interval
            while time.monotonic() < deadline:
                await asyncio.sleep(poll_interval)
                token_data = {
                    "grant_type": DEVICE_CODE_GRANT_TYPE,
                    "device_code": device_code,
                    "client_id": self.client_id,
                }
                if self.client_secret:
                    token_data["client_secret"] = self.client_secret

                async with session.post(
                    token_endpoint,
                    data=urlencode(token_data),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                ) as response:
                    payload = await response.json(content_type=None)
                    if response.status == 200:
                        return await self._finish_device_login(payload)

                    error = payload.get("error") if isinstance(payload, dict) else None
                    if error == "authorization_pending":
                        continue
                    if error == "slow_down":
                        # RFC 8628 section 3.5: increase by 5 seconds for all
                        # subsequent requests after a slow_down response.
                        poll_interval += 5
                        continue
                    if error == "access_denied":
                        raise RuntimeError("OAuth device authorization was denied")
                    if error == "expired_token":
                        raise RuntimeError("OAuth device code expired")
                    raise RuntimeError(
                        f"Device token exchange failed: HTTP {response.status} - {payload}"
                    )

        raise RuntimeError("OAuth device code expired before authorization completed")

    async def _finish_device_login(self, token_response: dict) -> dict:
        """Apply an RFC 8628 token response and resolve Matrix identity."""
        self.access_token = token_response.get("access_token")
        self.refresh_token = token_response.get("refresh_token")
        self.token_type = token_response.get("token_type", "Bearer")
        self.expires_in = token_response.get("expires_in")
        if not self.access_token:
            raise RuntimeError("Device token response did not contain access_token")

        self.client.access_token = self.access_token
        whoami = await self.client.whoami()
        self.device_id = whoami.get("device_id") or self.device_id
        _log("info", f"OAuth2 device login successful: {whoami.get('user_id')}")
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "user_id": whoami.get("user_id"),
            "device_id": self.device_id,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
        }
