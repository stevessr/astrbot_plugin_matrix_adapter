"""Matrix v1.18 account moderation operations (MSC4323)."""

from typing import Any

from ...path_utils import quote_path_segment


class UserAccountModerationMixin:
    """Admin-only stable account suspension and locking helpers."""

    async def get_user_suspension(self, user_id: str) -> dict[str, Any]:
        user = quote_path_segment(user_id)
        return await self._request("GET", f"/_matrix/client/v1/admin/suspend/{user}")

    async def set_user_suspension(
        self, user_id: str, suspended: bool
    ) -> dict[str, Any]:
        user = quote_path_segment(user_id)
        return await self._request(
            "PUT",
            f"/_matrix/client/v1/admin/suspend/{user}",
            data={"suspended": bool(suspended)},
        )

    async def get_user_lock(self, user_id: str) -> dict[str, Any]:
        user = quote_path_segment(user_id)
        return await self._request("GET", f"/_matrix/client/v1/admin/lock/{user}")

    async def set_user_lock(self, user_id: str, locked: bool) -> dict[str, Any]:
        user = quote_path_segment(user_id)
        return await self._request(
            "PUT",
            f"/_matrix/client/v1/admin/lock/{user}",
            data={"locked": bool(locked)},
        )
