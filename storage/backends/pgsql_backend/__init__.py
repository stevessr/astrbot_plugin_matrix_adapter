"""
PostgreSQL storage backend.
"""

from __future__ import annotations

from .connection import PgSQLBackendConnectionMixin
from .read import PgSQLBackendReadMixin
from .table import PgSQLBackendTableMixin
from .write import PgSQLBackendWriteMixin


class PgSQLBackend(
    PgSQLBackendConnectionMixin,
    PgSQLBackendTableMixin,
    PgSQLBackendReadMixin,
    PgSQLBackendWriteMixin,
):
    """One PostgreSQL table per folder namespace."""


# Preserve direct method attributes expected by callers using
# PgSQLBackend.__dict__ lookups.
for _mixin in (
    PgSQLBackendConnectionMixin,
    PgSQLBackendTableMixin,
    PgSQLBackendReadMixin,
    PgSQLBackendWriteMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if isinstance(_method, (staticmethod, classmethod)) or callable(_method):
            setattr(PgSQLBackend, _method_name, _method)


__all__ = ["PgSQLBackend"]
