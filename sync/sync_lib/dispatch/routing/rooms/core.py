"""Room-section dispatch for sync responses."""


class MatrixSyncManagerEventRoutingRoomsOrchestratorMixin:
    """Dispatch per-room sync response fields to callbacks."""

    def _dispatch_room_fields(self, sync_response: dict, tasks: list) -> None:
        rooms = sync_response.get("rooms", {})
        room_tasks = []

        join_rooms = rooms.get("join", {})
        self._dispatch_join_room_fields(join_rooms, room_tasks)

        invite_rooms = rooms.get("invite", {})
        self._dispatch_invite_room_fields(invite_rooms, room_tasks)

        leave_rooms = rooms.get("leave", {})
        self._dispatch_leave_room_fields(leave_rooms, room_tasks)

        knocked_rooms = rooms.get("knocked", {})
        self._dispatch_knock_room_fields(knocked_rooms, room_tasks)

        tasks.extend(room_tasks)


__all__ = ["MatrixSyncManagerEventRoutingRoomsOrchestratorMixin"]
