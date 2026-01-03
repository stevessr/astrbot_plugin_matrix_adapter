"""
Matrix HTTP Client - Widget Mixin
Provides widget management methods
"""

from typing import Any

from astrbot.api import logger


class WidgetMixin:
    """Widget management methods for Matrix client"""

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

    async def add_widget(
        self,
        room_id: str,
        widget_id: str,
        widget_type: str,
        url: str,
        name: str,
        data: dict[str, Any] | None = None,
        avatar_url: str | None = None,
        wait_for_iframe_load: bool = True,
    ) -> dict[str, Any]:
        """
        Add a widget to a room

        Args:
            room_id: Room ID
            widget_id: Unique widget ID
            widget_type: Widget type (e.g., 'customwidget', 'jitsi', 'etherpad')
            url: Widget URL (can include template variables like $matrix_room_id)
            name: Display name of the widget
            data: Optional additional data for the widget
            avatar_url: Optional avatar URL for the widget
            wait_for_iframe_load: Whether to wait for iframe to load

        Returns:
            Response with event_id
        """
        content: dict[str, Any] = {
            "type": widget_type,
            "url": url,
            "name": name,
            "id": widget_id,
            "creatorUserId": self.user_id,
            "waitForIframeLoad": wait_for_iframe_load,
        }

        if data:
            content["data"] = data
        if avatar_url:
            content["avatar_url"] = avatar_url

        # Use im.vector.modular.widgets for Element compatibility
        return await self.set_room_state_event(
            room_id=room_id,
            event_type="im.vector.modular.widgets",
            content=content,
            state_key=widget_id,
        )

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
