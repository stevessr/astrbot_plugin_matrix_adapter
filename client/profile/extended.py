"""
Matrix HTTP Client - Profile Extended Mixin
Provides extended profile and presence methods
"""

from typing import Any

from astrbot.api import logger

from ...constants import (
    M_PRESENCE_PROMPTED,
    M_PRESENCE_SHARING,
    M_ROOM_PRESENCE_SHARING,
    M_SELECTIVE_PRESENCE_CAP,
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
from ..path_utils import quote_path_segment


class ProfileExtendedMixin:
    """Extended profile and presence methods for Matrix client"""

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
                raise ValueError(
                    f"{label} must be a mapping user/room/server -> 'allow'|'deny'"
                )
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
