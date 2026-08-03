"""Matrix sync polling operations."""

from typing import Any

from astrbot.api import logger

from ....constants import DEFAULT_TIMEOUT_MS_30000


class AuthSyncPollingMixin:
    """Poll Matrix sync and maintain the next-batch token."""

    async def sync(
        self,
        since: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_MS_30000,
        full_state: bool = False,
        filter_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Sync with the Matrix server

        Args:
            since: Sync batch token from previous sync
            timeout: Timeout in milliseconds
            full_state: Whether to return full state
            filter_id: Filter ID for filtering events

        Returns:
            Sync response
        """
        params = {"timeout": timeout}
        if since:
            params["since"] = since
        if full_state:
            params["full_state"] = "true"
        if filter_id:
            params["filter"] = filter_id

        # HTTP timeout must exceed sync poll timeout to account for network latency
        http_timeout_s = timeout / 1000 + 15
        response = await self._request(
            "GET",
            "/_matrix/client/v3/sync",
            params=params,
            timeout_override=http_timeout_s,
        )

        # Log to_device events
        to_device = response.get("to_device", {}).get("events", [])
        if to_device:
            logger.info(
                f"SYNC: Received {len(to_device)} to_device events: {[e.get('type') for e in to_device]}"
            )

        # Store next_batch for future syncs
        self._next_batch = response.get("next_batch")

        return response
