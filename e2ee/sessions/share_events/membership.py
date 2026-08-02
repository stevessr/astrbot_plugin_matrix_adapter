"""Room-member lifecycle hooks for room-key sharing."""

from ...constants import (
    HISTORY_VISIBILITY_INVITED,
    HISTORY_VISIBILITY_JOINED,
    INVITE_KEY_SHARE_VISIBILITIES,
)


class E2EEManagerSessionShareEventsMembershipMixin:
    """按成员加入、邀请和离开事件轮换或补发房间密钥。"""

    async def on_room_member_joined(self, room_id: str, user_id: str) -> None:
        """Share allowed history, or rotate before encrypting for a new member."""
        if user_id == self.user_id:
            return
        self.invalidate_room_members_cache(room_id)

        metadata_getter = getattr(
            self._olm,
            "get_megolm_outbound_shared_history",
            None,
        )
        shared_history = metadata_getter(room_id) if callable(metadata_getter) else None
        if shared_history is not True:
            # A non-shareable (or legacy/unknown) session must not be handed to
            # a user who joined after it was created. The next send creates and
            # distributes a fresh session to the current membership instead.
            self._discard_outbound_session(room_id)
            return

        await self._share_existing_room_key(
            room_id=room_id,
            target_users=[user_id],
            reason="member_join",
            force_members_refresh=True,
        )

    async def on_room_member_invited(self, room_id: str, user_id: str) -> None:
        """Apply history-visibility rules when an encrypted-room invite lands."""
        if user_id == self.user_id:
            return
        self.invalidate_room_members_cache(room_id)
        visibility = await self._get_room_history_visibility(
            room_id,
            force_refresh=True,
        )
        if visibility == HISTORY_VISIBILITY_JOINED:
            return
        if visibility == HISTORY_VISIBILITY_INVITED:
            # An invitee may read messages sent after the invite, but must not
            # receive the session that encrypted messages from before it.
            self._discard_outbound_session(room_id)
            return
        if visibility not in INVITE_KEY_SHARE_VISIBILITIES:
            return

        metadata_getter = getattr(
            self._olm,
            "get_megolm_outbound_shared_history",
            None,
        )
        if callable(metadata_getter) and metadata_getter(room_id) is True:
            await self._share_existing_room_key(
                room_id=room_id,
                target_users=[user_id],
                reason="member_invite",
                force_members_refresh=True,
            )

    async def on_room_member_left(self, room_id: str, user_id: str) -> None:
        """Rotate so a departed or banned member cannot decrypt future events."""
        self.invalidate_room_members_cache(room_id)
        if user_id == self.user_id:
            return
        self._discard_outbound_session(room_id)
