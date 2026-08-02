"""Basic presence and MSC4133 extended profile operations."""

from typing import Any

from ....constants import MSC4133_PROFILE_PATH
from ...path_utils import quote_path_segment


class ProfileBasicMixin:
    """Presence status and extended profile field operations."""

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

    async def get_extended_profile(self, user_id: str | None = None) -> dict[str, Any]:
        """
        Fetch the full extended profile for a user (MSC4133).

        Falls back to the stable C-S ``/profile/{user_id}`` endpoint if the
        unstable MSC4133 endpoint is unavailable.
        """
        target = user_id or self.user_id
        if not target:
            raise Exception("user_id is required for get_extended_profile")
        try:
            encoded_target = quote_path_segment(target)
            return await self._request(
                "GET",
                f"{MSC4133_PROFILE_PATH}/{encoded_target}",
                authenticated=False,
            )
        except Exception:
            encoded_target = quote_path_segment(target)
            return await self._request(
                "GET",
                f"/_matrix/client/v3/profile/{encoded_target}",
                authenticated=False,
            )

    async def set_extended_profile_field(
        self, field: str, value: Any
    ) -> dict[str, Any]:
        """Set a single extended profile field (MSC4133)."""
        if not field:
            raise ValueError("field is required")
        user = quote_path_segment(self.user_id)
        profile_field = quote_path_segment(field)
        endpoint = f"{MSC4133_PROFILE_PATH}/{user}/{profile_field}"
        return await self._request("PUT", endpoint, data={field: value})

    async def delete_extended_profile_field(self, field: str) -> dict[str, Any]:
        """Remove a single extended profile field (MSC4133)."""
        if not field:
            raise ValueError("field is required")
        user = quote_path_segment(self.user_id)
        profile_field = quote_path_segment(field)
        endpoint = f"{MSC4133_PROFILE_PATH}/{user}/{profile_field}"
        return await self._request("DELETE", endpoint)


__all__ = ["ProfileBasicMixin"]
