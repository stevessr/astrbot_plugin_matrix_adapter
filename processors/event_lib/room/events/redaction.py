"""Redaction handling for Matrix room events."""

from astrbot.api import logger

from .....client.event_types import parse_event


class MatrixEventProcessorRoomRedactionMixin:
    """Handle redactions and update cached current room state when affected."""

    @staticmethod
    def _redaction_target_id(event_data: dict, content: dict) -> str:
        """Read ``redacts`` across pre-v11 and v11+ room event shapes."""
        value = content.get("redacts") if isinstance(content, dict) else None
        if not isinstance(value, str) or not value:
            value = event_data.get("redacts")
        return value if isinstance(value, str) else ""

    async def _refresh_redacted_current_state(
        self,
        room,
        redact_event_id: str,
    ) -> None:
        """Apply a redacted state event if it is still the room's current state.

        The homeserver already performs room-version-specific redaction, so use
        the server-returned target content instead of reimplementing redaction
        key rules locally.  Prefer the v1.16 ``format=event`` state lookup to
        prove the target is current; older homeservers fall back to comparing
        the current content.
        """
        client = getattr(self, "client", None)
        get_event = getattr(client, "get_event", None)
        get_state = getattr(client, "get_room_state_event", None)
        if not callable(get_event) or not callable(get_state):
            return

        try:
            target = await get_event(room.room_id, redact_event_id)
        except Exception as exc:
            logger.debug(f"获取被 redaction 的目标事件失败：{exc}")
            return
        if not isinstance(target, dict) or "state_key" not in target:
            return

        event_type = target.get("type")
        state_key = target.get("state_key")
        target_content = target.get("content")
        if not isinstance(event_type, str) or not isinstance(state_key, str):
            return
        if not isinstance(target_content, dict):
            target_content = {}

        is_current = False
        current_event = None
        try:
            current_event = await get_state(
                room.room_id,
                event_type,
                state_key,
                format="event",
            )
            if isinstance(current_event, dict):
                is_current = current_event.get("event_id") == redact_event_id
        except Exception:
            # ``format=event`` is v1.16+. For older homeservers compare the
            # current content returned by the long-standing endpoint.
            try:
                current_content = await get_state(room.room_id, event_type, state_key)
                is_current = (
                    isinstance(current_content, dict)
                    and current_content == target_content
                )
            except Exception as exc:
                logger.debug(f"确认 redacted state 是否仍为 current 失败：{exc}")
                return

        if not is_current:
            return

        authoritative = current_event if isinstance(current_event, dict) else target
        authoritative = dict(authoritative)
        authoritative.setdefault("type", event_type)
        authoritative.setdefault("state_key", state_key)
        authoritative["content"] = dict(
            authoritative.get("content")
            if isinstance(authoritative.get("content"), dict)
            else target_content
        )
        self._apply_room_state_event(room, authoritative)
        await self._persist_room_state(room)

    async def _handle_redaction_event(
        self, room, event_data: dict, content: dict
    ) -> bool:
        redact_event_id = self._redaction_target_id(event_data, content)
        if redact_event_id:
            await self._refresh_redacted_current_state(room, redact_event_id)

        event = parse_event(event_data, room.room_id)
        await self._process_message_event(room, event)
        return True
