"""
Common helpers for storage backends.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_STORAGE_BACKEND_ALIASES = {
    "json": "json",
    "sqlite": "sqlite",
    "pgsql": "pgsql",
    "postgres": "pgsql",
    "postgresql": "pgsql",
}


def normalize_storage_backend(value: str | None) -> str:
    """Normalize storage backend value to json/sqlite/pgsql."""
    if not isinstance(value, str):
        return "json"
    normalized = value.strip().lower()
    return _STORAGE_BACKEND_ALIASES.get(normalized, "json")


def _sanitize_pg_identifier(value: str, fallback: str) -> str:
    identifier = re.sub(r"[^a-zA-Z0-9_]+", "_", (value or "").strip()).strip("_")
    if not identifier:
        identifier = fallback
    if identifier[0].isdigit():
        identifier = f"_{identifier}"
    return identifier.lower()


def normalize_pg_identifier(value: str, fallback: str) -> str:
    """Expose pg identifier sanitizer to backend modules."""
    return _sanitize_pg_identifier(value, fallback)


def build_pg_table_name(namespace_key: str, prefix: str = "matrix_store") -> str:
    """
    Build a valid PostgreSQL table name from namespace.

    PostgreSQL identifier length limit is 63 bytes.
    """
    safe_prefix = _sanitize_pg_identifier(prefix, "matrix_store")
    safe_namespace = _sanitize_pg_identifier(namespace_key.replace("/", "_"), "store")
    digest = hashlib.sha1(namespace_key.encode("utf-8")).hexdigest()[:8]

    base = f"{safe_prefix}_{safe_namespace}"
    max_base_len = 63 - len(digest) - 1
    if len(base) > max_base_len:
        base = base[:max_base_len].rstrip("_")
    if not base:
        base = safe_prefix
    return f"{base}_{digest}"


def build_folder_namespace(folder_path: Path, base_path: Path | None = None) -> str:
    """Build stable namespace key for one folder."""
    if base_path is not None:
        try:
            return folder_path.relative_to(base_path).as_posix()
        except Exception:
            pass
    return folder_path.as_posix()
