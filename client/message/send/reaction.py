"""Matrix reaction send operations."""

import time
from typing import Any

from ....constants import REL_TYPE_ANNOTATION
from ...path_utils import quote_path_segment


class MessageReactionMixin:
    """Send ``m.reaction`` annotation events."""

    async def send_reaction(
        self, room_id: str, event_id: str, emoji: str
    ) -> dict[str, Any]:
        """
        Send a reaction to an event

        According to Matrix spec, reactions use the m.reaction event type
        with m.relates_to containing rel_type: m.annotation

        Args:
            room_id: Room ID
            event_id: Event ID to react to
            emoji: The emoji to react with (e.g., "👍", "❤️")

        Returns:
            Response with event_id of the reaction
        """
        txn_id = f"{int(time.time() * 1000)}_{id(emoji)}"
        room = quote_path_segment(room_id)
        txn = quote_path_segment(txn_id)
        endpoint = f"/_matrix/client/v3/rooms/{room}/send/m.reaction/{txn}"

        content = {
            "m.relates_to": {
                "rel_type": REL_TYPE_ANNOTATION,
                "event_id": event_id,
                "key": emoji,
            }
        }

        return await self._request("PUT", endpoint, data=content)


__all__ = ["MessageReactionMixin"]
