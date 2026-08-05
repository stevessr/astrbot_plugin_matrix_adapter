"""Room member record upsert orchestration."""

from .core import MatrixRoomMemberRecordsUpsertMixin
from .fields import MatrixRoomMemberRecordsFieldsMixin
from .lookup import MatrixRoomMemberRecordsLookupMixin
from .persist import MatrixRoomMemberRecordsPersistMixin


class MatrixRoomMemberRecordsCoreMixin(MatrixRoomMemberRecordsUpsertMixin):
    """Persist room member records through a guarded upsert flow."""

    pass


# Preserve direct method attributes expected by parent mixins.
for _mixin in (
    MatrixRoomMemberRecordsUpsertMixin,
    MatrixRoomMemberRecordsFieldsMixin,
    MatrixRoomMemberRecordsLookupMixin,
    MatrixRoomMemberRecordsPersistMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if _method_name.startswith("__"):
            continue
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixRoomMemberRecordsCoreMixin, _method_name, _method)


__all__ = [
    "MatrixRoomMemberRecordsCoreMixin",
    "MatrixRoomMemberRecordsFieldsMixin",
    "MatrixRoomMemberRecordsLookupMixin",
    "MatrixRoomMemberRecordsPersistMixin",
    "MatrixRoomMemberRecordsUpsertMixin",
]
