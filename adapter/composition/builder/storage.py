"""Storage initialization for adapter service composition."""

from __future__ import annotations

from pathlib import Path

from ....config.matrix import MatrixConfig
from ....storage.paths import MatrixStoragePaths
from ....storage.stores.outbound import MatrixOutboundTracker


def _init_storage(matrix_config: MatrixConfig) -> tuple[Path, MatrixOutboundTracker]:
    """Prepare the user storage directory and outbound tracker."""
    user_storage_dir = MatrixStoragePaths.get_user_storage_dir(
        matrix_config.store_path,
        matrix_config.homeserver,
        matrix_config.user_id,
    )
    MatrixStoragePaths.ensure_directory(user_storage_dir, treat_as_file=False)

    storage_backend_config = getattr(matrix_config, "storage_backend_config", None)
    backend = storage_backend_config.backend if storage_backend_config else "json"
    pgsql_dsn = storage_backend_config.pgsql_dsn if storage_backend_config else ""
    pgsql_schema = (
        storage_backend_config.pgsql_schema if storage_backend_config else "public"
    )
    pgsql_table_prefix = (
        storage_backend_config.pgsql_table_prefix
        if storage_backend_config
        else "matrix_store"
    )

    outbound_tracker = MatrixOutboundTracker(
        user_storage_dir=user_storage_dir,
        store_path=matrix_config.store_path,
        backend=backend,
        pgsql_dsn=pgsql_dsn,
        pgsql_schema=pgsql_schema,
        pgsql_table_prefix=pgsql_table_prefix,
    )
    return user_storage_dir, outbound_tracker
