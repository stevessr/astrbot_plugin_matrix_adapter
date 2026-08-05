"""Matrix widget update operation."""

from typing import Any


class WidgetUpdateMixin:
    """Update existing room widgets."""

    async def update_widget(
        self,
        room_id: str,
        widget_id: str,
        url: str | None = None,
        name: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Update an existing widget

        Args:
            room_id: Room ID
            widget_id: Widget ID to update
            url: New URL (optional)
            name: New name (optional)
            data: New data (optional)

        Returns:
            Response with event_id
        """
        # Get current widget state
        try:
            current = await self.get_room_state_event(
                room_id, "im.vector.modular.widgets", widget_id
            )
        except Exception:
            raise Exception(f"Widget {widget_id} not found in room {room_id}")

        # Update fields
        if url is not None:
            current["url"] = url
        if name is not None:
            current["name"] = name
        if data is not None:
            current["data"] = data

        return await self.set_room_state_event(
            room_id=room_id,
            event_type="im.vector.modular.widgets",
            content=current,
            state_key=widget_id,
        )


__all__ = ["WidgetUpdateMixin"]
