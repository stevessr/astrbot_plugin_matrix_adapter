"""Matrix global and room account-data operations."""

from math import isfinite
from typing import Any

from ...path_utils import quote_path_segment

RECENT_EMOJI_ACCOUNT_DATA = "m.recent_emoji"
INVITE_PERMISSION_CONFIG_ACCOUNT_DATA = "m.invite_permission_config"
RECENT_EMOJI_RECOMMENDED_LIMIT = 100
MAX_SAFE_JSON_INTEGER = 2**53


class ProfileAccountDataMixin:
    async def get_global_account_data(self, type: str) -> dict[str, Any]:
        """
        Get user global account data

        Args:
            type: Account data type (e.g., m.direct)

        Returns:
            Account data content
        """
        # Ensure user_id is set (it should be after login)
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")

        user = quote_path_segment(self.user_id)
        data_type = quote_path_segment(type)
        endpoint = f"/_matrix/client/v3/user/{user}/account_data/{data_type}"
        try:
            return await self._request("GET", endpoint)
        except Exception:
            # Return empty dict if not found (404)
            return {}

    async def set_global_account_data(
        self, type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Set user global account data

        Args:
            type: Account data type (e.g., m.direct)
            content: Account data content

        Returns:
            Empty dict on success
        """
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")
        user = quote_path_segment(self.user_id)
        data_type = quote_path_segment(type)
        endpoint = f"/_matrix/client/v3/user/{user}/account_data/{data_type}"
        return await self._request("PUT", endpoint, data=content)

    async def get_recent_emoji(self) -> list[dict[str, Any]]:
        """Return the stable Matrix v1.18 ``m.recent_emoji`` list (MSC4356)."""
        content = await self.get_global_account_data(RECENT_EMOJI_ACCOUNT_DATA)
        recent = content.get("recent_emoji", []) if isinstance(content, dict) else []
        return list(recent) if isinstance(recent, list) else []

    async def set_recent_emoji(
        self, recent_emoji: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Replace ``m.recent_emoji`` account data after validating its schema."""
        normalized = self._normalize_recent_emoji(recent_emoji, limit=None)
        if len(normalized) != len(recent_emoji):
            raise ValueError(
                "recent_emoji contains entries which do not conform to Matrix v1.18"
            )
        return await self.set_global_account_data(
            RECENT_EMOJI_ACCOUNT_DATA, {"recent_emoji": normalized}
        )

    async def record_recent_emoji(
        self,
        emoji: str,
        *,
        increment: int | float = 1,
        limit: int = RECENT_EMOJI_RECOMMENDED_LIMIT,
    ) -> list[dict[str, Any]]:
        """Record one emoji use according to MSC4356 client behaviour.

        The used emoji is moved to the front, its cumulative counter is increased,
        invalid entries are removed, and the list is truncated to the spec's
        recommended maximum of 100 entries by default.
        """
        if not isinstance(emoji, str) or not emoji:
            raise ValueError("emoji must be a non-empty string")
        if isinstance(increment, bool) or not isinstance(increment, (int, float)):
            raise ValueError("increment must be a number")
        if not isfinite(float(increment)) or increment <= 0:
            raise ValueError("increment must be a finite positive number")
        if limit < 1:
            raise ValueError("limit must be at least 1")

        recent = self._normalize_recent_emoji(await self.get_recent_emoji(), limit=None)
        old_total: int | float = 0
        preserved: list[dict[str, Any]] = []
        for entry in recent:
            if entry["emoji"] == emoji:
                old_total = entry["total"]
            else:
                preserved.append(entry)

        new_total = old_total + increment
        if not isfinite(float(new_total)) or new_total >= MAX_SAFE_JSON_INTEGER:
            raise ValueError("recent emoji total must be smaller than 2^53")

        updated = [{"emoji": emoji, "total": new_total}, *preserved][:limit]
        await self.set_global_account_data(
            RECENT_EMOJI_ACCOUNT_DATA, {"recent_emoji": updated}
        )
        return updated

    @staticmethod
    def _normalize_recent_emoji(
        recent_emoji: list[Any], *, limit: int | None
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for entry in recent_emoji:
            if not isinstance(entry, dict):
                continue
            emoji = entry.get("emoji")
            total = entry.get("total")
            if not isinstance(emoji, str):
                continue
            if isinstance(total, bool) or not isinstance(total, (int, float)):
                continue
            if not isfinite(float(total)) or total < 0 or total >= MAX_SAFE_JSON_INTEGER:
                continue
            # Keep unknown emoji strings and extension keys intact, as required by
            # MSC4356, while normalising the two stable schema fields.
            normalized.append({**entry, "emoji": emoji, "total": total})
            if limit is not None and len(normalized) >= limit:
                break
        return normalized

    async def get_invite_blocking(self) -> bool:
        """Return whether stable Matrix v1.18 invite blocking is enabled (MSC4380)."""
        content = await self.get_global_account_data(
            INVITE_PERMISSION_CONFIG_ACCOUNT_DATA
        )
        return isinstance(content, dict) and content.get("default_action") == "block"

    async def set_invite_blocking(self, enabled: bool) -> dict[str, Any]:
        """Enable or disable stable Matrix v1.18 invite blocking (MSC4380)."""
        content: dict[str, Any] = {"default_action": "block"} if enabled else {}
        return await self.set_global_account_data(
            INVITE_PERMISSION_CONFIG_ACCOUNT_DATA, content
        )

    async def get_room_account_data(self, room_id: str, type: str) -> dict[str, Any]:
        """
        Get room account data for current user

        Args:
            room_id: Room ID
            type: Account data type

        Returns:
            Account data content
        """
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")
        user = quote_path_segment(self.user_id)
        room = quote_path_segment(room_id)
        data_type = quote_path_segment(type)
        endpoint = (
            f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
        )
        try:
            return await self._request("GET", endpoint)
        except Exception:
            return {}

    async def set_room_account_data(
        self, room_id: str, type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Set room account data for current user

        Args:
            room_id: Room ID
            type: Account data type
            content: Account data content

        Returns:
            Empty dict on success
        """
        if not hasattr(self, "user_id") or not self.user_id:
            raise Exception("Client not logged in or user_id not set")
        user = quote_path_segment(self.user_id)
        room = quote_path_segment(room_id)
        data_type = quote_path_segment(type)
        endpoint = (
            f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
        )
        return await self._request("PUT", endpoint, data=content)
