"""Room member record field-diff merge logic."""

from .merge import _merge_optional_fields, _merge_required_fields


class MatrixRoomMemberRecordsDiffCoreMixin:
    """Compare incoming member fields against an existing record."""

    def _merge_room_record_diff(self, existing: dict, **kwargs) -> bool:
        """Apply any changed fields to ``existing``.

        Returns True when at least one field changed.
        """
        updated = False

        if _merge_required_fields(existing, kwargs):
            updated = True

        if _merge_optional_fields(existing, kwargs):
            updated = True

        return updated
