"""Invite-room section dispatch for sync responses."""

import asyncio


class MatrixSyncManagerEventRoutingRoomsInviteMixin:
    """Dispatch invite-section room fields to callbacks."""

    def _dispatch_invite_room_fields(
        self, invite_rooms: dict, room_tasks: list
    ) -> None:
        """Queue invite callbacks for each invited room."""
        # Invite events
        for room_id, invite_data in invite_rooms.items():
            if self.on_invite:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_invite:{room_id}",
                            self.on_invite,
                            room_id,
                            invite_data,
                        )
                    )
                )


__all__ = ["MatrixSyncManagerEventRoutingRoomsInviteMixin"]
