"""Existing-room record lookup for upserts."""


class MatrixRoomMemberRecordsLookupMixin:
    """Load the existing record, or seed a new entry."""

    def _load_existing_record(self, room_id: str) -> tuple[dict, bool]:
        # If no existing data, this is a new entry
        existing = self.get(room_id)
        if not existing:
            existing = {"room_id": room_id}
            return existing, True
        return existing, False
