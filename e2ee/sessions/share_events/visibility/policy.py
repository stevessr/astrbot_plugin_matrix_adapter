"""History-visibility policy normalization and room lookup."""

from astrbot.api import logger

from .....constants import M_ROOM_HISTORY_VISIBILITY
from ....constants import (
    DEFAULT_HISTORY_VISIBILITY,
    HISTORY_VISIBILITY_JOINED,
    SHAREABLE_HISTORY_VISIBILITIES,
    VALID_HISTORY_VISIBILITIES,
)


class E2EEManagerSessionShareEventsVisibilityPolicyMixin:
    """缓存房间加密配置并解析历史可见性策略。"""

    @staticmethod
    def _normalize_history_visibility(value: object) -> str:
        if isinstance(value, str) and value in VALID_HISTORY_VISIBILITIES:
            return value
        # Matrix defines a missing/invalid history visibility as ``shared``.
        return DEFAULT_HISTORY_VISIBILITY

    @classmethod
    def _history_visibility_is_shareable(cls, value: object) -> bool:
        return (
            cls._normalize_history_visibility(value) in SHAREABLE_HISTORY_VISIBILITIES
        )

    async def _get_room_history_visibility(
        self,
        room_id: str,
        *,
        force_refresh: bool = False,
    ) -> str:
        """Resolve and cache the room's normalized history visibility.

        A missing state event has the Matrix default of ``shared``.  A
        transient request failure is handled conservatively as ``joined`` and
        is not cached, so no key is exposed to an invitee based on stale data.
        """
        cache = getattr(self, "_room_history_visibility", None)
        if not isinstance(cache, dict):
            cache = {}
            self._room_history_visibility = cache
        if not force_refresh and room_id in cache:
            return self._normalize_history_visibility(cache[room_id])

        try:
            content = await self.client.get_room_state_event(
                room_id,
                M_ROOM_HISTORY_VISIBILITY,
                "",
            )
        except Exception as e:
            if getattr(e, "status", None) == 404:
                cache[room_id] = DEFAULT_HISTORY_VISIBILITY
                return DEFAULT_HISTORY_VISIBILITY
            logger.warning(
                "Failed to read room history visibility; defaulting "
                f"conservatively to joined: room={room_id} error={e}"
            )
            return HISTORY_VISIBILITY_JOINED

        visibility = (
            content.get("history_visibility") if isinstance(content, dict) else None
        )
        normalized = self._normalize_history_visibility(visibility)
        cache[room_id] = normalized
        return normalized

    async def _get_room_shared_history(
        self,
        room_id: str,
        *,
        force_refresh: bool = False,
    ) -> bool:
        """Resolve whether new Megolm sessions may be shared with invitees.

        Matrix treats an absent/unknown ``m.room.history_visibility`` event as
        ``shared``. Transient request failures are handled conservatively and
        are not cached, so a later send can retry.
        """
        visibility = await self._get_room_history_visibility(
            room_id,
            force_refresh=force_refresh,
        )
        return self._history_visibility_is_shareable(visibility)
