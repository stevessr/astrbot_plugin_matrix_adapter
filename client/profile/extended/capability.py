"""MSC4495 capability and room presence sharing operations."""

from typing import Any

from astrbot.api import logger

from ....constants import (
    M_ROOM_PRESENCE_SHARING,
    M_SELECTIVE_PRESENCE_CAP,
    MSC4495_CAPABILITY,
    MSC4495_ROOM_PRESENCE_SHARING,
    MSC4495_SELECTIVE_PRESENCE_CAP,
    PRESENCE_HINT_FORBID,
    PRESENCE_HINT_SUGGEST,
)
from ...path_utils import quote_path_segment


class PresenceCapabilityMixin:
    """Probe selective-presence support and manage room sharing hints."""

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


__all__ = ["PresenceCapabilityMixin"]
