"""Composable Matrix room member storage operations."""

import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools

from ....config.plugin import get_plugin_config
from ...backend import MatrixFolderDataStore
from ...paths import MatrixStoragePaths
from .cache import MatrixRoomCacheMixin
from .records import MatrixRoomMemberRecordsMixin
from .storage import MatrixRoomStorageMixin


class MatrixRoomMemberStore(
    MatrixRoomStorageMixin,
    MatrixRoomCacheMixin,
    MatrixRoomMemberRecordsMixin,
):
    """Persist room member lists and metadata."""

    _MAX_CACHE_ENTRIES = 512

    def __init__(
        self,
        data_dir: Path | None = None,
    ) -> None:
        if data_dir is None:
            try:
                data_dir = StarTools.get_data_dir("astrbot_plugin_matrix_adapter")
            except Exception:
                data_dir = Path("./data/astrbot_plugin_matrix_adapter")
        self._rooms_dir = data_dir / "rooms"
        self._rooms_dir.mkdir(parents=True, exist_ok=True)
        self._cache: OrderedDict[str, dict[str, Any]] = OrderedDict()

        self._storage_backend_config = get_plugin_config().storage_backend_config
        self._storage_backend = self._storage_backend_config.backend
        self._pgsql_dsn = self._storage_backend_config.pgsql_dsn
        self._pgsql_schema = self._storage_backend_config.pgsql_schema
        self._pgsql_table_prefix = self._storage_backend_config.pgsql_table_prefix

        self._store = self._build_store()


# Preserve direct method attributes exposed by the former monolithic store.
for _mixin in (
    MatrixRoomStorageMixin,
    MatrixRoomCacheMixin,
    MatrixRoomMemberRecordsMixin,
):
    for _method_name, _method in _mixin.__dict__.items():
        if callable(_method) and not _method_name.startswith("__"):
            setattr(MatrixRoomMemberStore, _method_name, _method)


__all__ = [
    "Any",
    "MatrixFolderDataStore",
    "MatrixRoomCacheMixin",
    "MatrixRoomMemberRecordsMixin",
    "MatrixRoomMemberStore",
    "MatrixRoomStorageMixin",
    "MatrixStoragePaths",
    "OrderedDict",
    "Path",
    "StarTools",
    "get_plugin_config",
    "logger",
    "time",
]
