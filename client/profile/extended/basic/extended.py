"""MSC4133 extended profile field operations."""

from typing import Any

from .....constants import MSC4133_PROFILE_PATH
from ....path_utils import quote_path_segment


class ProfileExtendedFieldsMixin:
    """Extended profile field operations (MSC4133)."""

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


__all__ = ["ProfileExtendedFieldsMixin"]
