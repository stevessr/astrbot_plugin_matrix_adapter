"""Leave-room section dispatch for sync responses."""

import asyncio


class MatrixSyncManagerEventRoutingRoomsLeaveMixin:
    """Dispatch leave-section room fields to callbacks."""

    def _dispatch_leave_room_fields(self, leave_rooms: dict, room_tasks: list) -> None:
        """Queue leave callbacks for each left room."""
        # Leave events
        for room_id, leave_data in leave_rooms.items():
            if self.on_leave:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_leave:{room_id}",
                            self.on_leave,
                            room_id,
                            leave_data,
                        )
                    )
                )


__all__ = ["MatrixSyncManagerEventRoutingRoomsLeaveMixin"]
