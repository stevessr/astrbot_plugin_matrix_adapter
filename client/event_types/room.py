"""Matrix room metadata model."""

from dataclasses import dataclass, field
from typing import Any

from ...constants import GROUP_CHAT_MIN_MEMBERS_2


@dataclass
class MatrixRoom:
    """Represents a Matrix room."""

    room_id: str
    display_name: str = ""
    topic: str = ""
    avatar_url: str | None = None
    join_rules: dict[str, Any] | None = None
    power_levels: dict[str, Any] | None = None
    history_visibility: str | None = None
    guest_access: str | None = None
    canonical_alias: str | None = None
    room_aliases: list[str] = field(default_factory=list)
    encryption: dict[str, Any] | None = None
    create: dict[str, Any] | None = None
    tombstone: dict[str, Any] | None = None
    pinned_events: list[str] = field(default_factory=list)
    space_children: dict[str, dict[str, Any]] = field(default_factory=dict)
    space_parents: dict[str, dict[str, Any]] = field(default_factory=dict)
    third_party_invites: dict[str, dict[str, Any]] = field(default_factory=dict)
    state_events: dict[str, dict[str, Any]] = field(default_factory=dict)
    live_messaging_enabled: bool | None = None
    timeline_limited: bool = False
    member_count: int = 0
    is_direct: bool | None = None
    members: dict[str, str] = field(default_factory=dict)  # user_id -> display_name
    member_avatars: dict[str, str] = field(default_factory=dict)  # user_id -> mxc url

    def user_name(self, user_id: str) -> str:
        """Get display name for a user."""
        return self.members.get(user_id, user_id)

    @property
    def is_group(self) -> bool:
        """Check if room is a group (more than 2 members)."""
        # is_direct=True 明确标记为私聊
        if self.is_direct is True:
            return False
        # 其他情况用成员数判断
        effective_count = self.member_count or len(self.members)
        return effective_count > GROUP_CHAT_MIN_MEMBERS_2
