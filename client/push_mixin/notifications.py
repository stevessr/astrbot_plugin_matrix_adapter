"""Matrix pusher and notification operations."""

from typing import Any


class PushNotificationMixin:
    """Manage registered pushers and notification queries."""

    async def get_pushers(self) -> dict[str, Any]:
        """
        Get registered pushers
        """
        return await self._request("GET", "/_matrix/client/v3/pushers")

    async def set_pusher(self, pusher: dict[str, Any]) -> dict[str, Any]:
        """
        Create or update a pusher
        """
        return await self._request(
            "POST", "/_matrix/client/v3/pushers/set", data=pusher
        )

    async def get_notifications(
        self, from_token: str, limit: int | None = None, only: str | None = None
    ) -> dict[str, Any]:
        """
        Get notifications
        """
        params: dict[str, Any] = {"from": from_token}
        if limit is not None:
            params["limit"] = limit
        if only:
            params["only"] = only
        return await self._request(
            "GET", "/_matrix/client/v3/notifications", params=params
        )
