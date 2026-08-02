"""MSC4495 presence sharing preference operations."""

from typing import Any

from astrbot.api import logger

from ....constants import (
    M_PRESENCE_SHARING,
    MSC4495_PRESENCE_SHARING,
    PRESENCE_SHARING_ALLOW,
    PRESENCE_SHARING_DENY,
)


class PresenceSharingMixin:
    """Read and write account-data presence sharing preferences."""

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


__all__ = ["PresenceSharingMixin"]
