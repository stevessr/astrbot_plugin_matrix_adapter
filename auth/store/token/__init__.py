"""High-level authentication token persistence."""

from .load import MatrixAuthStoreTokenLoadMixin
from .save import MatrixAuthStoreTokenSaveMixin


class MatrixAuthStoreTokenMixin(
    MatrixAuthStoreTokenSaveMixin,
    MatrixAuthStoreTokenLoadMixin,
):
    """Save and load complete authentication sessions."""


# Preserve direct method attributes exposed by the former flat mixin:
# callers use Mixin.__dict__ lookups, which miss inherited methods.
for _mixin in (
    MatrixAuthStoreTokenSaveMixin,
    MatrixAuthStoreTokenLoadMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(MatrixAuthStoreTokenMixin, _method_name, _method)


__all__ = [
    "MatrixAuthStoreTokenLoadMixin",
    "MatrixAuthStoreTokenMixin",
    "MatrixAuthStoreTokenSaveMixin",
]
