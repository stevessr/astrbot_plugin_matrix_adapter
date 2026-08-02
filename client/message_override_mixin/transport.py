"""Hook-aware wrappers around message and event requests."""

from typing import Any


class MessageOverrideTransportMixin:
    async def send_message(
        self,
        room_id: str,
        msg_type: str,
        content: dict[str, Any],
        txn_id: str | None = None,
        tracker_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        content = await self.before_send_message(room_id, msg_type, content)
        response = await super().send_message(
            room_id,
            msg_type,
            content,
            txn_id=txn_id,
            tracker_metadata=tracker_metadata,
        )
        return await self.after_send_message(room_id, msg_type, content, response)

    async def get_event(self, room_id: str, event_id: str) -> dict[str, Any]:
        cached = await self.before_get_event(room_id, event_id)
        if cached is not None:
            return cached
        event = await super().get_event(room_id, event_id)
        return await self.after_get_event(room_id, event_id, event)

    async def room_messages(
        self,
        room_id: str,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict[str, Any]:
        # 钩子可就地改写 params 以调整查询，或返回非 None 直接短路。
        params: dict[str, Any] = {
            "from_token": from_token,
            "to_token": to_token,
            "direction": direction,
            "limit": limit,
        }
        cached = await self.before_room_messages(room_id, params)
        if cached is not None:
            return cached
        response = await super().room_messages(
            room_id,
            from_token=params.get("from_token"),
            to_token=params.get("to_token"),
            direction=params.get("direction", "b"),
            limit=params.get("limit", 10),
        )
        return await self.after_room_messages(room_id, params, response)
