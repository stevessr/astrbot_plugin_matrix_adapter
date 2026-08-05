"""Existing outbound room-key sharing."""


class E2EEManagerSessionShareKeysExistingMixin:
    """Share an existing outbound Megolm session to selected users."""

    async def _share_existing_room_key(
        self,
        room_id: str,
        target_users: list[str] | None = None,
        reason: str = "proactive",
        force_members_refresh: bool = False,
    ) -> None:
        """Share an existing outbound Megolm session key to selected users."""
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            return

        session_info = self._olm.get_megolm_outbound_session_info(room_id)
        if not session_info:
            return
        session_id, session_key = session_info

        members = await self._get_room_members(
            room_id, force_refresh=force_members_refresh
        )

        if not members:
            return

        await self.ensure_room_keys_sent(
            room_id=room_id,
            members=members,
            session_id=session_id,
            session_key=session_key,
            target_users=target_users,
            reason=reason,
        )


__all__ = ["E2EEManagerSessionShareKeysExistingMixin"]
