"""Join-room section dispatch for sync responses."""

import asyncio


class MatrixSyncManagerEventRoutingRoomsJoinMixin:
    """Dispatch join-section room fields to callbacks."""

    def _dispatch_join_room_fields(self, join_rooms: dict, room_tasks: list) -> None:
        """Queue join, ephemeral, and room account data callbacks."""
        # Join events
        for room_id, room_data in join_rooms.items():
            if self.on_room_event:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_room_event:{room_id}",
                            self.on_room_event,
                            room_id,
                            room_data,
                        )
                    )
                )
            # Ephemeral events per room
            ephemeral = room_data.get("ephemeral", {})
            ephemeral_events = ephemeral.get("events", [])
            if ephemeral_events and self.on_ephemeral_event:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_ephemeral_event:{room_id}",
                            self.on_ephemeral_event,
                            room_id,
                            ephemeral_events,
                        )
                    )
                )
            # Room account data
            room_account_data = room_data.get("account_data", {})
            room_account_data_events = room_account_data.get("events", [])
            if room_account_data_events and self.on_room_account_data:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_room_account_data:{room_id}",
                            self.on_room_account_data,
                            room_id,
                            room_account_data_events,
                        )
                    )
                )


__all__ = ["MatrixSyncManagerEventRoutingRoomsJoinMixin"]
