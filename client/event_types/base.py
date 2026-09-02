"""Base Matrix event model and shared deserialization."""

from dataclasses import dataclass
from typing import Any


@dataclass
class MatrixEvent:
    """Base class for Matrix events."""

    event_id: str
    sender: str
    origin_server_ts: int
    room_id: str
    content: dict[str, Any]
    event_type: str
    state_key: str | None = None
    unsigned: dict[str, Any] | None = None

    @property
    def replaces_state(self) -> str | None:
        """Event ID replaced by this state event (Matrix v1.19).

        Homeservers expose this as ``unsigned.replaces_state`` even when
        ``unsigned.prev_content`` is hidden by history visibility.
        """
        if not isinstance(self.unsigned, dict):
            return None
        event_id = self.unsigned.get("replaces_state")
        return event_id if isinstance(event_id, str) and event_id else None

    @property
    def unsigned_membership(self) -> str | None:
        """Membership associated with the event via Matrix v1.11 / MSC4115.

        The homeserver may expose the requesting user's membership in
        ``unsigned.membership``. Keep this separate from ``m.room.member``
        content membership so generic timeline events can expose it safely.
        """
        if not isinstance(self.unsigned, dict):
            return None
        membership = self.unsigned.get("membership")
        return membership if isinstance(membership, str) and membership else None

    @classmethod
    def from_dict(cls, data: dict[str, Any], room_id: str):
        """Create event from dictionary."""
        return cls(
            event_id=data.get("event_id", ""),
            sender=data.get("sender", ""),
            origin_server_ts=data.get("origin_server_ts", 0),
            room_id=room_id,
            content=data.get("content", {}),
            event_type=data.get("type", ""),
            state_key=data.get("state_key"),
            unsigned=data.get("unsigned"),
        )
