"""MSC4140 delayed event listing and lifecycle operations."""

from typing import Any

from ...constants import MSC4140_DELAYED_EVENTS_PATH
from ..path_utils import quote_path_segment


class DelayedEventManagementMixin:
    """List and manage pending delayed events."""

    async def list_delayed_events(
        self,
        from_token: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """List the user's currently pending delayed events (MSC4140)."""
        params: dict[str, Any] = {}
        if from_token:
            params["from"] = from_token
        if limit is not None:
            params["limit"] = limit
        return await self._request(
            "GET", MSC4140_DELAYED_EVENTS_PATH, params=params or None
        )

    async def manage_delayed_event(self, delay_id: str, action: str) -> dict[str, Any]:
        """
        Run an action against a pending delayed event (MSC4140).

        Args:
            delay_id: The delay ID returned by ``send_delayed_*``.
            action: One of ``send``, ``restart``, ``cancel``.
        """
        action = (action or "").strip().lower()
        if action not in {"send", "restart", "cancel"}:
            raise ValueError("action must be one of 'send', 'restart', 'cancel'")
        delay = quote_path_segment(delay_id)
        endpoint = f"{MSC4140_DELAYED_EVENTS_PATH}/{delay}"
        return await self._request("POST", endpoint, data={"action": action})

    async def cancel_delayed_event(self, delay_id: str) -> dict[str, Any]:
        """Cancel a pending delayed event (MSC4140)."""
        return await self.manage_delayed_event(delay_id, "cancel")

    async def restart_delayed_event(self, delay_id: str) -> dict[str, Any]:
        """Restart the timer on a pending delayed event (MSC4140)."""
        return await self.manage_delayed_event(delay_id, "restart")

    async def fire_delayed_event(self, delay_id: str) -> dict[str, Any]:
        """Send a pending delayed event immediately (MSC4140)."""
        return await self.manage_delayed_event(delay_id, "send")
