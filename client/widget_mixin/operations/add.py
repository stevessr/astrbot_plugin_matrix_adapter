"""Matrix widget add operation."""

from typing import Any


class WidgetAddMixin:
    """Create room widgets."""

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


__all__ = ["WidgetAddMixin"]
