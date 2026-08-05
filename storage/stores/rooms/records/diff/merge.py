"""Room member record merge helpers."""

from .fields import _MERGE_ALWAYS_FIELDS, _MERGE_IF_NOT_NONE_FIELDS


def _merge_required_fields(existing: dict, kwargs: dict) -> bool:
    """Merge always-present fields; return True when any changed."""
    updated = False
    for field in _MERGE_ALWAYS_FIELDS:
        value = kwargs.get(field)
        if value != existing.get(field):
            existing[field] = value
            updated = True
    return updated


def _merge_optional_fields(existing: dict, kwargs: dict) -> bool:
    """Merge explicitly provided optional fields; return True when any changed."""
    updated = False
    for field in _MERGE_IF_NOT_NONE_FIELDS:
        value = kwargs.get(field)
        if value is not None and value != existing.get(field):
            existing[field] = value
            updated = True
    return updated
