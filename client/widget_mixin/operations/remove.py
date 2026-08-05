"""Matrix widget remove operation."""

from typing import Any


class WidgetRemoveMixin:
    """Remove room widgets."""

    async def remove_widget(self, room_id: str, widget_id: str) -> dict[str, Any]:
        """
        Remove a widget from a room

        Args:
            room_id: Room ID
            widget_id: Widget ID to remove

        Returns:
            Response with event_id
        """
        # Removing a widget is done by sending an empty content
        return await self.set_room_state_event(
            room_id=room_id,
            event_type="im.vector.modular.widgets",
            content={},
            state_key=widget_id,
        )


__all__ = ["WidgetRemoveMixin"]
