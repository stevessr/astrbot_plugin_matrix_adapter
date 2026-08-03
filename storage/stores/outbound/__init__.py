"""Composable Matrix outbound tracking operations."""

from __future__ import annotations

import copy
import time
from pathlib import Path
from typing import Any

from astrbot.api import logger

from ...backend import MatrixFolderDataStore, build_folder_namespace
from .lifecycle import MatrixOutboundLifecycleMixin
from .records import MatrixOutboundRecordsMixin
from .resend import MatrixOutboundResendMixin


class MatrixOutboundTracker(
    MatrixOutboundLifecycleMixin,
    MatrixOutboundRecordsMixin,
    MatrixOutboundResendMixin,
):
    """Persist outbound room sends so failed sends can be diagnosed/resubmitted."""

    _TERMINAL_STATES = {"sent", "failed"}

    def __init__(
        self,
        *,
        user_storage_dir: Path,
        store_path: str | Path,
        backend: str,
        pgsql_dsn: str = "",
        pgsql_schema: str = "public",
        pgsql_table_prefix: str = "matrix_store",
    ) -> None:
        self.user_storage_dir = Path(user_storage_dir)
        self.folder_path = self.user_storage_dir / "outbound"
        namespace = build_folder_namespace(self.folder_path, Path(store_path))
        self.store = MatrixFolderDataStore(
            folder_path=self.folder_path,
            namespace_key=namespace,
            backend=backend,
            sqlite_db_filename="outbound.db",
            pgsql_dsn=pgsql_dsn,
            pgsql_schema=pgsql_schema,
            pgsql_table_prefix=pgsql_table_prefix,
        )
        self._recent_keys_key = "__recent_keys__"
        self._record_limit = 200


# Preserve direct method attributes exposed by the former monolithic tracker.
for _mixin in (
    MatrixOutboundLifecycleMixin,
    MatrixOutboundRecordsMixin,
    MatrixOutboundResendMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixOutboundTracker, _method_name, _method)


__all__ = [
    "Any",
    "MatrixFolderDataStore",
    "MatrixOutboundLifecycleMixin",
    "MatrixOutboundRecordsMixin",
    "MatrixOutboundResendMixin",
    "MatrixOutboundTracker",
    "Path",
    "build_folder_namespace",
    "copy",
    "logger",
    "time",
]
