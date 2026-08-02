"""Room-member state queries and cache population."""

import time

from astrbot.api import logger

from ....constants import (
    M_ROOM_ENCRYPTION,
    M_ROOM_HISTORY_VISIBILITY,
    M_ROOM_MEMBER,
    MEMBERSHIP_INVITE,
    MEMBERSHIP_JOIN,
)
from ...constants import (
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
    INVITE_KEY_SHARE_VISIBILITIES,
)


class E2EEManagerSessionShareEventsMembersMixin:
    """查询、过滤并缓存房间成员列表。"""

    async def _get_room_members(
        self, room_id: str, force_refresh: bool = False
    ) -> list[str]:
        """获取房间成员列表"""
        cache = getattr(self, "_room_members_cache", None)
        cache_ttl = float(
            getattr(
                self,
                "_room_members_cache_ttl_sec",
                DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
            )
        )
        if (
            not force_refresh
            and isinstance(cache, dict)
            and room_id in cache
            and isinstance(cache[room_id], tuple)
            and len(cache[room_id]) == 2
        ):
            members, ts = cache[room_id]
            if (time.monotonic() - float(ts)) <= cache_ttl:
                return list(members)

        try:
            state = await self.client.get_room_state(room_id)
            visibility = None
            for event in state:
                if (
                    event.get("type") == M_ROOM_ENCRYPTION
                    and event.get("state_key", "") == ""
                ):
                    self.set_room_encryption_config(
                        room_id,
                        event.get("content") or {},
                    )
                if (
                    event.get("type") == M_ROOM_HISTORY_VISIBILITY
                    and event.get("state_key", "") == ""
                ):
                    visibility = (event.get("content") or {}).get("history_visibility")
            if visibility is None:
                visibility = await self._get_room_history_visibility(room_id)
            else:
                visibility = self._normalize_history_visibility(visibility)
                history_cache = getattr(self, "_room_history_visibility", None)
                if not isinstance(history_cache, dict):
                    history_cache = {}
                    self._room_history_visibility = history_cache
                history_cache[room_id] = visibility
            include_invited = visibility in INVITE_KEY_SHARE_VISIBILITIES
            members = []
            for event in state:
                if event.get("type") == M_ROOM_MEMBER:
                    membership = event.get("content", {}).get("membership")
                    if membership == MEMBERSHIP_JOIN or (
                        include_invited and membership == MEMBERSHIP_INVITE
                    ):
                        state_key = event.get("state_key")
                        if state_key:
                            members.append(state_key)
            unique_members = list(dict.fromkeys(members))
            if isinstance(cache, dict):
                cache[room_id] = (unique_members, time.monotonic())
            return unique_members
        except Exception as e:
            logger.warning(f"获取房间成员失败：{e}")
            return []
