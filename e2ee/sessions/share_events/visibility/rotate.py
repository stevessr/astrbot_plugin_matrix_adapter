"""Megolm rotation on history-visibility audience changes."""

from astrbot.api import logger

from ....constants import INVITE_KEY_SHARE_VISIBILITIES


class E2EEManagerSessionShareEventsVisibilityRotateMixin:
    """缓存房间加密配置并解析历史可见性策略。"""

    async def on_history_visibility_changed(
        self,
        room_id: str,
        previous: object,
        current: object,
    ) -> None:
        """Rotate Megolm when history visibility changes its key audience."""
        normalized_previous = self._normalize_history_visibility(previous)
        normalized_current = self._normalize_history_visibility(current)
        cache = getattr(self, "_room_history_visibility", None)
        if isinstance(cache, dict):
            cache[room_id] = normalized_current
        self.invalidate_room_members_cache(room_id)

        previous_policy = (
            self._history_visibility_is_shareable(normalized_previous),
            normalized_previous in INVITE_KEY_SHARE_VISIBILITIES,
        )
        current_policy = (
            self._history_visibility_is_shareable(normalized_current),
            normalized_current in INVITE_KEY_SHARE_VISIBILITIES,
        )
        if previous_policy == current_policy:
            return

        if self._discard_outbound_session(room_id):
            logger.info(
                "房间历史可见性改变，已轮换 Megolm 出站会话："
                f"room={room_id} previous={previous} current={normalized_current}"
            )
