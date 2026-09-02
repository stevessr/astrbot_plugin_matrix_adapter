"""Matrix v1.16 / MSC4133 extended profile field operations."""

from typing import Any

from .....constants import (
    M_PROFILE_TIME_ZONE,
    MSC4133_PROFILE_PATH,
)
from ....base.errors import MatrixAPIError
from ....path_utils import quote_path_segment


class ProfileExtendedFieldsMixin:
    """Stable extended profile field operations with legacy MSC fallback."""

    @staticmethod
    def _should_fallback_to_unstable_profile(error: MatrixAPIError) -> bool:
        """Only fall back for servers that do not implement stable custom fields.

        Permission, validation, and rate-limit failures from a stable endpoint
        must propagate rather than being bypassed through an unstable route.
        """
        return error.status in {404, 405} or error.errcode == "M_UNRECOGNIZED"

    async def get_extended_profile(self, user_id: str | None = None) -> dict[str, Any]:
        """Fetch the full profile using the Matrix v1.16 stable endpoint."""
        target = user_id or self.user_id
        if not target:
            raise Exception("user_id is required for get_extended_profile")
        encoded_target = quote_path_segment(target)
        stable_endpoint = f"/_matrix/client/v3/profile/{encoded_target}"
        try:
            return await self._request(
                "GET",
                stable_endpoint,
                authenticated=False,
            )
        except MatrixAPIError as error:
            if not self._should_fallback_to_unstable_profile(error):
                raise
            return await self._request(
                "GET",
                f"{MSC4133_PROFILE_PATH}/{encoded_target}",
                authenticated=False,
            )

    async def get_extended_profile_field(
        self,
        field: str,
        user_id: str | None = None,
    ) -> Any | None:
        """Fetch one stable custom profile field and return its value."""
        if not isinstance(field, str) or not field:
            raise ValueError("field is required")
        target = user_id or self.user_id
        if not target:
            raise Exception("user_id is required for get_extended_profile_field")
        encoded_target = quote_path_segment(target)
        profile_field = quote_path_segment(field)
        stable_endpoint = f"/_matrix/client/v3/profile/{encoded_target}/{profile_field}"
        try:
            response = await self._request(
                "GET",
                stable_endpoint,
                authenticated=False,
            )
        except MatrixAPIError as error:
            if not self._should_fallback_to_unstable_profile(error):
                raise
            response = await self._request(
                "GET",
                f"{MSC4133_PROFILE_PATH}/{encoded_target}/{profile_field}",
                authenticated=False,
            )
        if not isinstance(response, dict):
            return None
        return response.get(field)

    async def set_extended_profile_field(
        self, field: str, value: Any
    ) -> dict[str, Any]:
        """Set one Matrix v1.16 stable custom profile field."""
        if not isinstance(field, str) or not field:
            raise ValueError("field is required")

        can_set = getattr(self, "can_set_profile_field", None)
        if callable(can_set):
            permission = await can_set(field)
            if permission is False:
                raise PermissionError(
                    f"Homeserver m.profile_fields capability forbids profile field {field!r}"
                )

        user = quote_path_segment(self.user_id)
        profile_field = quote_path_segment(field)
        data = {field: value}
        stable_endpoint = f"/_matrix/client/v3/profile/{user}/{profile_field}"
        try:
            return await self._request("PUT", stable_endpoint, data=data)
        except MatrixAPIError as error:
            if not self._should_fallback_to_unstable_profile(error):
                raise
            return await self._request(
                "PUT",
                f"{MSC4133_PROFILE_PATH}/{user}/{profile_field}",
                data=data,
            )

    async def delete_extended_profile_field(self, field: str) -> dict[str, Any]:
        """Delete one Matrix v1.16 stable custom profile field."""
        if not isinstance(field, str) or not field:
            raise ValueError("field is required")

        can_set = getattr(self, "can_set_profile_field", None)
        if callable(can_set):
            permission = await can_set(field)
            if permission is False:
                raise PermissionError(
                    f"Homeserver m.profile_fields capability forbids profile field {field!r}"
                )

        user = quote_path_segment(self.user_id)
        profile_field = quote_path_segment(field)
        stable_endpoint = f"/_matrix/client/v3/profile/{user}/{profile_field}"
        try:
            return await self._request("DELETE", stable_endpoint)
        except MatrixAPIError as error:
            if not self._should_fallback_to_unstable_profile(error):
                raise
            return await self._request(
                "DELETE",
                f"{MSC4133_PROFILE_PATH}/{user}/{profile_field}",
            )

    async def get_profile_timezone(self, user_id: str | None = None) -> str | None:
        """Read the Matrix v1.16 / MSC4175 stable ``m.tz`` profile field.

        The value is deliberately not validated against the local IANA database:
        Matrix allows clients and servers to have different database versions.
        Invalid/non-string values are treated as unset.
        """
        value = await self.get_extended_profile_field(M_PROFILE_TIME_ZONE, user_id)
        return value if isinstance(value, str) and value else None

    async def set_profile_timezone(self, timezone_name: str) -> dict[str, Any]:
        """Set the stable ``m.tz`` field to an IANA time-zone name."""
        if not isinstance(timezone_name, str) or not timezone_name.strip():
            raise ValueError("timezone_name must be a non-empty string")
        return await self.set_extended_profile_field(
            M_PROFILE_TIME_ZONE,
            timezone_name.strip(),
        )

    async def delete_profile_timezone(self) -> dict[str, Any]:
        """Remove the stable ``m.tz`` profile field."""
        return await self.delete_extended_profile_field(M_PROFILE_TIME_ZONE)


__all__ = ["ProfileExtendedFieldsMixin"]
