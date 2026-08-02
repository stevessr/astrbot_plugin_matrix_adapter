"""Storage backend configuration model."""

from dataclasses import dataclass

from ..backends import normalize_storage_backend


@dataclass(frozen=True)
class StorageBackendConfig:
    """Runtime storage backend config shared across components."""

    backend: str = "json"
    pgsql_dsn: str = ""
    pgsql_schema: str = "public"
    pgsql_table_prefix: str = "matrix_store"

    @classmethod
    def create(
        cls,
        *,
        backend: str | None = None,
        pgsql_dsn: str | None = None,
        pgsql_schema: str | None = None,
        pgsql_table_prefix: str | None = None,
    ) -> "StorageBackendConfig":
        return cls(
            backend=normalize_storage_backend(backend),
            pgsql_dsn=(pgsql_dsn or "").strip(),
            pgsql_schema=(pgsql_schema or "public").strip() or "public",
            pgsql_table_prefix=(pgsql_table_prefix or "matrix_store").strip()
            or "matrix_store",
        )


__all__ = ["StorageBackendConfig"]
