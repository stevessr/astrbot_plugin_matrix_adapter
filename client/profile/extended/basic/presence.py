"""Basic presence operations."""

from typing import Any

from ....path_utils import quote_path_segment


class ProfilePresenceMixin:
    """Presence status operations."""

    async def set_presence(
        self,
        status: str = "online",
        status_msg: str | None = None,
        last_active_ts: int | None = None,
        currently_active: bool | None = None,
    ) -> dict[str, Any]:
        """
        Set user presence status

        Args:
            status: Presence status ('online', 'unavailable', 'offline',
                or 'busy' per MSC3026)
            status_msg: Optional status message
            last_active_ts: Optional last active timestamp (ms)
            currently_active: Optional active flag

        Returns:
            Empty dict on success
        """
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/presence/{user}/status"
        data: dict[str, Any] = {"presence": status}
        if status_msg:
            data["status_msg"] = status_msg
        if last_active_ts is not None:
            data["last_active_ts"] = last_active_ts
        if currently_active is not None:
            data["currently_active"] = currently_active
        return await self._request("PUT", endpoint, data=data)

    async def get_presence(self, user_id: str) -> dict[str, Any]:
        """
        Get user presence status

        Args:
            user_id: Matrix user ID

        Returns:
            Presence response
        """
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/presence/{user}/status"
        return await self._request("GET", endpoint)


__all__ = ["ProfilePresenceMixin"]
