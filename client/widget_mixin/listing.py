"""Matrix widget listing operations."""

from typing import Any

from astrbot.api import logger


class WidgetListingMixin:
    """List active widgets in a room."""

    async def get_widgets(self, room_id: str) -> list[dict[str, Any]]:
        """
        Get all widgets in a room

        Args:
            room_id: Room ID

        Returns:
            List of widget state events
        """
        try:
            state = await self.get_room_state(room_id)
            widgets = []
            for event in state:
                # Check both widget event types
                if event.get("type") in ["im.vector.modular.widgets", "m.widget"]:
                    # Only include active widgets (non-empty content)
                    if event.get("content"):
                        widgets.append(event)
            return widgets
        except Exception as e:
            logger.error(f"Failed to get widgets for room {room_id}: {e}")
            return []
