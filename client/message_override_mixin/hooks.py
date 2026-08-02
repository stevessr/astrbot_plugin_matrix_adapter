"""Default overridable message hook methods."""

from typing import Any


class MessageOverrideHooksMixin:
    async def before_send_message(
        self, room_id: str, msg_type: str, content: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "before_send_message", content, room_id, msg_type
        )

    async def after_send_message(
        self,
        room_id: str,
        msg_type: str,
        content: dict[str, Any],
        response: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "after_send_message", response, room_id, msg_type, content
        )

    async def before_get_event(
        self, room_id: str, event_id: str
    ) -> dict[str, Any] | None:
        return await self._short_circuit_via_hooks(
            "before_get_event", room_id, event_id
        )

    async def after_get_event(
        self, room_id: str, event_id: str, event: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "after_get_event", event, room_id, event_id
        )

    async def before_room_messages(
        self, room_id: str, params: dict[str, Any]
    ) -> dict[str, Any] | None:
        return await self._short_circuit_via_hooks(
            "before_room_messages", room_id, params
        )

    async def after_room_messages(
        self, room_id: str, params: dict[str, Any], response: dict[str, Any]
    ) -> dict[str, Any]:
        return await self._transform_via_hooks(
            "after_room_messages", response, room_id, params
        )
