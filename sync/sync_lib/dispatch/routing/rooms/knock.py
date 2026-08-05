"""Knock-room section dispatch for sync responses."""

import asyncio


class MatrixSyncManagerEventRoutingRoomsKnockMixin:
    """Dispatch knock-section room fields to callbacks."""

    def _dispatch_knock_room_fields(
        self, knocked_rooms: dict, room_tasks: list
    ) -> None:
        """Queue knock callbacks for each pending-knock room."""
        # Knock events (MSC2403) — rooms the user has knocked on
        # where membership is still pending.
        for room_id, knock_data in knocked_rooms.items():
            if self.on_knock:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_knock:{room_id}",
                            self.on_knock,
                            room_id,
                            knock_data,
                        )
                    )
                )


__all__ = ["MatrixSyncManagerEventRoutingRoomsKnockMixin"]
