"""Mutual-room discovery operations."""

from typing import Any


class UserMutualRoomsMixin:
    """Find rooms shared with another Matrix user."""

    async def get_mutual_rooms(
        self,
        user_id: str,
        from_token: str | None = None,
    ) -> dict[str, Any]:
        """Get one page of rooms shared with another user (Matrix v1.19).

        ``next_batch`` from the response can be supplied as ``from_token`` to
        fetch the next page.
        """
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("user_id must be a non-empty Matrix user ID")

        params: dict[str, str] = {"user_id": user_id.strip()}
        if from_token is not None:
            normalized_token = str(from_token).strip()
            if normalized_token:
                params["from"] = normalized_token
        return await self._request(
            "GET",
            "/_matrix/client/v1/mutual_rooms",
            params=params,
        )
