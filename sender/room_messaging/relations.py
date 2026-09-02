"""Room relation, receipt, and call-control sender extensions."""


class SenderRelationsMixin:
    async def get_message_relations(
        self,
        room_id: str,
        event_id: str,
        rel_type: str,
        *,
        event_type: str | None = None,
        from_token: str | None = None,
        to_token: str | None = None,
        limit: int | None = None,
        recurse: bool | None = None,
    ) -> dict:
        """Get Matrix relations, optionally recursively (v1.10 / MSC3981)."""
        kwargs = {
            "room_id": room_id,
            "event_id": event_id,
            "rel_type": rel_type,
            "event_type": event_type,
            "from_token": from_token,
            "to_token": to_token,
            "limit": limit,
        }
        if recurse is not None:
            kwargs["recurse"] = recurse
        return await self.client.get_event_relations(**kwargs)

    async def set_read_markers(
        self,
        room_id: str,
        *,
        fully_read: str | None = None,
        read: str | None = None,
        allow_backward: bool = False,
    ) -> dict:
        """Set room read markers.

        ``allow_backward`` (MSC4446) 允许把 ``m.fully_read`` 回移到更早的事件。
        """
        return await self.client.send_read_markers(
            room_id=room_id,
            fully_read=fully_read,
            read=read,
            allow_backward=allow_backward,
        )

    async def set_fully_read_marker(
        self,
        room_id: str,
        event_id: str,
        *,
        allow_backward: bool = False,
    ) -> dict:
        """把 fully read 标记移到指定事件（走 receipt 端点，MSC4446 aware）。"""
        return await self.client.send_fully_read_receipt(
            room_id=room_id,
            event_id=event_id,
            allow_backward=allow_backward,
        )

    async def send_call_decline(
        self,
        room_id: str,
        notification_event_id: str,
        *,
        reason: str | None = None,
    ) -> dict:
        """发送 MatrixRTC 通话拒接事件（MSC4310）。

        以 ``m.reference`` 关联指定的 ``m.rtc.notification`` 事件。
        """
        return await self.client.send_call_decline(
            room_id=room_id,
            notification_event_id=notification_event_id,
            reason=reason,
        )


__all__ = ["SenderRelationsMixin"]
