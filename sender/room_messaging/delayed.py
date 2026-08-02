"""Delayed-event sender extensions."""

from typing import Any


class SenderDelayedMixin:
    async def send_delayed_message(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        delay_ms: int,
        parent_delay_id: str | None = None,
    ) -> dict:
        """Schedule a delayed Matrix event (MSC4140)."""
        return await self.client.send_delayed_room_event(
            room_id=room_id,
            event_type=event_type,
            content=content,
            delay_ms=delay_ms,
            parent_delay_id=parent_delay_id,
        )

    async def cancel_delayed_message(self, delay_id: str) -> dict:
        """Cancel a previously scheduled delayed event (MSC4140)."""
        return await self.client.cancel_delayed_event(delay_id)

    async def fire_delayed_message(self, delay_id: str) -> dict:
        """Immediately fire a pending delayed event (MSC4140)."""
        return await self.client.fire_delayed_event(delay_id)

    async def restart_delayed_message(self, delay_id: str) -> dict:
        """Reset the timeout on a pending delayed event (MSC4140)."""
        return await self.client.restart_delayed_event(delay_id)

    async def list_delayed_messages(
        self, from_token: str | None = None, limit: int | None = None
    ) -> dict:
        """List currently pending delayed events (MSC4140)."""
        return await self.client.list_delayed_events(from_token=from_token, limit=limit)


__all__ = ["SenderDelayedMixin"]
