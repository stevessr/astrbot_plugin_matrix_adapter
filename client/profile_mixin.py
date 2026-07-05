"""
Matrix HTTP Client - Profile Mixin
Provides user profile and presence methods
"""

from typing import Any

from astrbot.api import logger

from ..constants import (
    M_MARKED_UNREAD,
    M_PRESENCE_PROMPTED,
    M_PRESENCE_SHARING,
    M_ROOM_PRESENCE_SHARING,
    M_SELECTIVE_PRESENCE_CAP,
    MSC2867_MARKED_UNREAD,
    MSC4133_PROFILE_PATH,
    MSC4495_CAPABILITY,
    MSC4495_PRESENCE_PROMPTED,
    MSC4495_PRESENCE_SHARING,
    MSC4495_ROOM_PRESENCE_SHARING,
    MSC4495_SELECTIVE_PRESENCE_CAP,
    PRESENCE_HINT_FORBID,
    PRESENCE_HINT_SUGGEST,
    PRESENCE_SHARING_ALLOW,
    PRESENCE_SHARING_DENY,
)
from .path_utils import quote_path_segment


class ProfileMixin:
    """Profile and presence methods for Matrix client"""

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
        endpoint = f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
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
        endpoint = f"/_matrix/client/v3/user/{user}/rooms/{room}/account_data/{data_type}"
        return await self._request("PUT", endpoint, data=content)

    async def set_display_name(self, display_name: str) -> dict[str, Any]:
        """
        Set user display name

        Args:
            display_name: New display name

        Returns:
            Response data
        """
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/displayname"
        return await self._request("PUT", endpoint, data={"displayname": display_name})

    async def get_display_name(self, user_id: str) -> str:
        """
        Get user display name

        Args:
            user_id: Matrix user ID

        Returns:
            Display name
        """
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/displayname"
        response = await self._request("GET", endpoint, authenticated=False)
        return response.get("displayname", user_id)

    async def get_avatar_url(self, user_id: str) -> str | None:
        """
        Get user avatar URL

        Args:
            user_id: Matrix user ID

        Returns:
            Avatar URL (mxc:// format) or None
        """
        user = quote_path_segment(user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/avatar_url"
        try:
            response = await self._request("GET", endpoint, authenticated=False)
            return response.get("avatar_url")
        except Exception:
            return None

    async def set_avatar_url(self, avatar_url: str) -> dict[str, Any]:
        """
        Set user avatar URL

        Args:
            avatar_url: New avatar URL (mxc:// format)

        Returns:
            Response data
        """
        user = quote_path_segment(self.user_id)
        endpoint = f"/_matrix/client/v3/profile/{user}/avatar_url"
        return await self._request("PUT", endpoint, data={"avatar_url": avatar_url})

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
            status: Presence status ('online', 'unavailable', 'offline')
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

    async def get_user_room(self, user_id: str) -> str | None:
        """
        Find a direct message room with the specified user

        Args:
            user_id: The user ID to find a DM room for

        Returns:
            The room ID if found, None otherwise
        """
        try:
            # Get direct chat map from account data
            account_data = await self.get_global_account_data("m.direct")
            content = account_data.get("content", {})

            # Look for rooms with this user
            rooms = content.get(user_id, [])
            if isinstance(rooms, list):
                for room_id in rooms:
                    room_id_text = str(room_id or "").strip()
                    if room_id_text:
                        return room_id_text

            return None
        except Exception as e:
            logger.warning(f"Failed to find DM room for {user_id}: {e}")
            return None

    async def set_room_marked_unread(
        self, room_id: str, unread: bool = True
    ) -> dict[str, Any]:
        """
        Mark a room as (un)read on the user's account (MSC2867).

        Writes both the stable ``m.marked_unread`` key (Matrix v1.12+) and the
        legacy ``com.famedly.marked_unread`` key for older clients/servers.
        """
        content = {"unread": bool(unread)}
        # Stable key (room account data)
        await self.set_room_account_data(room_id, M_MARKED_UNREAD, content)
        # Legacy unstable key for older clients
        try:
            await self.set_room_account_data(
                room_id, MSC2867_MARKED_UNREAD, content
            )
        except Exception as e:
            logger.debug(f"Failed to set legacy marked_unread: {e}")
        return content

    async def get_room_marked_unread(self, room_id: str) -> bool:
        """Read the marked-unread state of a room (MSC2867)."""
        for type_key in (M_MARKED_UNREAD, MSC2867_MARKED_UNREAD):
            try:
                data = await self.get_room_account_data(room_id, type_key)
            except Exception:
                continue
            content = data.get("content") if isinstance(data, dict) else None
            if isinstance(content, dict) and "unread" in content:
                return bool(content.get("unread"))
            if isinstance(data, dict) and "unread" in data:
                return bool(data.get("unread"))
        return False

    async def get_extended_profile(
        self, user_id: str | None = None
    ) -> dict[str, Any]:
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

    # --- MSC4495 Selective Presence ---------------------------------------

    def _validate_presence_sharing_maps(
        self,
        users: dict[str, str] | None,
        rooms: dict[str, str] | None,
        servers: dict[str, str] | None,
    ) -> None:
        """校验 MSC4495 presence sharing map 的语义约束。"""
        valid = {PRESENCE_SHARING_ALLOW, PRESENCE_SHARING_DENY}
        for label, mapping, forbidden in (
            ("users", users, None),
            ("rooms", rooms, PRESENCE_SHARING_DENY),
            ("servers", servers, PRESENCE_SHARING_ALLOW),
        ):
            if mapping is None:
                continue
            if not isinstance(mapping, dict):
                raise ValueError(f"{label} must be a mapping user/room/server -> 'allow'|'deny'")
            for key, value in mapping.items():
                if value not in valid:
                    raise ValueError(
                        f"{label}['{key}'] = {value!r} must be 'allow' or 'deny'"
                    )
                if forbidden and value == forbidden:
                    raise ValueError(
                        f"{label}['{key}'] must not be '{forbidden}' (MSC4495 constraint)"
                    )

    async def get_presence_sharing_prefs(self) -> dict[str, Any]:
        """读取 ``m.presence.sharing`` account data（MSC4495）。

        优先读取稳定键，回退到 unstable 键。返回归一化后的 content（不含
        account_data 包装），缺失时返回默认 ``{}``。
        """
        for type_key in (M_PRESENCE_SHARING, MSC4495_PRESENCE_SHARING):
            try:
                data = await self.get_global_account_data(type_key)
            except Exception:
                continue
            content = data.get("content") if isinstance(data, dict) else None
            if isinstance(content, dict) and content:
                return content
            if isinstance(data, dict) and data and "content" not in data:
                # 直接是 content（部分实现不包装）
                return data
        return {}

    async def set_presence_sharing_prefs(
        self,
        *,
        share_locally: bool | None = None,
        users: dict[str, str] | None = None,
        rooms: dict[str, str] | None = None,
        servers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """写入 ``m.presence.sharing`` account data（MSC4495）。

        同时写入稳定键 ``m.presence.sharing`` 与 unstable 键
        ``org.continuwuity.presence_v2.msc4495.presence.sharing``，兼容尚未支持
        稳定名的服务器。语义约束：``rooms`` 值不可为 ``"deny"``、``servers``
        值不可为 ``"allow"``。
        """
        self._validate_presence_sharing_maps(users, rooms, servers)
        content: dict[str, Any] = {}
        if share_locally is not None:
            content["share_locally"] = bool(share_locally)
        if users is not None:
            content["users"] = dict(users)
        if rooms is not None:
            content["rooms"] = dict(rooms)
        if servers is not None:
            content["servers"] = dict(servers)
        await self.set_global_account_data(M_PRESENCE_SHARING, content)
        try:
            await self.set_global_account_data(MSC4495_PRESENCE_SHARING, content)
        except Exception as e:
            logger.debug(f"Failed to set unstable presence.sharing: {e}")
        return content

    async def get_presence_prompted(self) -> dict[str, Any]:
        """读取 ``m.presence.prompted`` account data（MSC4495）。"""
        for type_key in (M_PRESENCE_PROMPTED, MSC4495_PRESENCE_PROMPTED):
            try:
                data = await self.get_global_account_data(type_key)
            except Exception:
                continue
            content = data.get("content") if isinstance(data, dict) else None
            if isinstance(content, dict) and content:
                return content
            if isinstance(data, dict) and data and "content" not in data:
                return data
        return {"users": [], "rooms": []}

    async def set_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        """覆盖写入 ``m.presence.prompted``（MSC4495），同时双栈写入。"""
        content: dict[str, Any] = {
            "users": list(users) if users is not None else [],
            "rooms": list(rooms) if rooms is not None else [],
        }
        await self.set_global_account_data(M_PRESENCE_PROMPTED, content)
        try:
            await self.set_global_account_data(MSC4495_PRESENCE_PROMPTED, content)
        except Exception as e:
            logger.debug(f"Failed to set unstable presence.prompted: {e}")
        return content

    async def _modify_presence_prompted(
        self,
        *,
        add_users: list[str] | None = None,
        add_rooms: list[str] | None = None,
        remove_users: list[str] | None = None,
        remove_rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        current = await self.get_presence_prompted()
        users_list: list[str] = list(current.get("users") or [])
        rooms_list: list[str] = list(current.get("rooms") or [])

        def _add(target: list[str], additions: list[str] | None) -> None:
            if not additions:
                return
            existing = set(target)
            for item in additions:
                if item and item not in existing:
                    target.append(item)
                    existing.add(item)

        def _remove(target: list[str], removals: list[str] | None) -> None:
            if not removals:
                return
            remove_set = set(removals)
            target[:] = [x for x in target if x not in remove_set]

        _add(users_list, add_users)
        _add(rooms_list, add_rooms)
        _remove(users_list, remove_users)
        _remove(rooms_list, remove_rooms)
        return await self.set_presence_prompted(users=users_list, rooms=rooms_list)

    async def add_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        """把 user/room 加入 ``m.presence.prompted`` 数组（去重，MSC4495）。"""
        return await self._modify_presence_prompted(add_users=users, add_rooms=rooms)

    async def remove_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        """把 user/room 从 ``m.presence.prompted`` 数组移除（MSC4495）。"""
        return await self._modify_presence_prompted(
            remove_users=users, remove_rooms=rooms
        )

    async def get_selective_presence_capability(self) -> bool:
        """探测服务器是否支持 Selective Presence（MSC4495）。

        优先读 ``GET /capabilities`` 的 ``m.selective_presence``，回退到
        unstable capability 键，再回退到 ``GET /versions`` 的
        ``unstable_features`` 中是否列出 ``org.continuwuity.presence_v2.msc4495``。
        """
        try:
            caps = await self.get_capabilities()
            if isinstance(caps, dict):
                capabilities = caps.get("capabilities") or caps
                if isinstance(capabilities, dict):
                    if capabilities.get(M_SELECTIVE_PRESENCE_CAP):
                        return True
                    if capabilities.get(MSC4495_SELECTIVE_PRESENCE_CAP):
                        return True
        except Exception as e:
            logger.debug(f"Failed to query capabilities for selective presence: {e}")
        try:
            user_val = quote_path_segment(self.user_id) if self.user_id else ""
            endpoint = "/_matrix/client/versions"
            versions = await self._request("GET", endpoint, authenticated=False)
            if isinstance(versions, dict):
                unstable_features = versions.get("unstable_features") or {}
                if isinstance(unstable_features, dict):
                    if unstable_features.get(MSC4495_CAPABILITY):
                        return True
                    if unstable_features.get(MSC4495_SELECTIVE_PRESENCE_CAP):
                        return True
        except Exception as e:
            logger.debug(f"Failed to query /versions for selective presence: {e}")
        _ = user_val  # 仅避免未使用告警
        return False

    # --- MSC4495 Room presence sharing hint -------------------------------

    async def set_room_presence_sharing(
        self, room_id: str, hint: str
    ) -> dict[str, Any]:
        """写入房间 ``m.room.presence_sharing`` 状态事件（MSC4495）。

        ``hint`` 必须为 ``"suggest"`` 或 ``"forbid"``。同时写入稳定与 unstable
        状态事件类型。
        """
        if hint not in (PRESENCE_HINT_SUGGEST, PRESENCE_HINT_FORBID):
            raise ValueError(
                f"hint must be '{PRESENCE_HINT_SUGGEST}' or '{PRESENCE_HINT_FORBID}'"
            )
        content = {"presence_sharing": hint}
        # 房间状态事件无 account_data 包装，双栈写两份状态事件
        await self.set_room_state_event(room_id, M_ROOM_PRESENCE_SHARING, content)
        try:
            await self.set_room_state_event(
                room_id, MSC4495_ROOM_PRESENCE_SHARING, content
            )
        except Exception as e:
            logger.debug(f"Failed to set unstable room.presence_sharing: {e}")
        return content

    async def get_room_presence_sharing(self, room_id: str) -> str | None:
        """读取房间 ``m.room.presence_sharing`` hint（MSC4495）。

        返回 ``"suggest"``/``"forbid"``；事件缺失时按规范默认视为 ``"forbid"``。
        """
        for type_key in (M_ROOM_PRESENCE_SHARING, MSC4495_ROOM_PRESENCE_SHARING):
            try:
                data = await self.get_room_state_event(room_id, type_key)
            except Exception:
                continue
            content = data.get("content") if isinstance(data, dict) else None
            if isinstance(content, dict) and content.get("presence_sharing"):
                return str(content.get("presence_sharing"))
            if isinstance(data, dict) and data.get("presence_sharing"):
                return str(data.get("presence_sharing"))
        return None
