"""Room-section dispatch for sync responses."""

import asyncio


class MatrixSyncManagerEventRoutingRoomsMixin:
    """Dispatch per-room sync response fields to callbacks."""

    def _dispatch_room_fields(self, sync_response: dict, tasks: list) -> None:
        rooms = sync_response.get("rooms", {})
        room_tasks = []

        # Join events
        join_rooms = rooms.get("join", {})
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

        # Invite events
        invite_rooms = rooms.get("invite", {})
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

        # Leave events
        leave_rooms = rooms.get("leave", {})
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

        # Knock events (MSC2403) — rooms the user has knocked on
        # where membership is still pending.
        knocked_rooms = rooms.get("knocked", {})
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

        tasks.extend(room_tasks)
