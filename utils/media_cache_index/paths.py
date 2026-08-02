"""Media cache index path conversion helpers."""

from pathlib import Path


class MediaCacheIndexPathsMixin:
    @property
    def db_path(self) -> Path:
        return self._db_path

    def _to_rel_path(self, path: Path) -> str:
        resolved_path = path.resolve()
        resolved_cache_dir = self._cache_dir.resolve()
        try:
            return resolved_path.relative_to(resolved_cache_dir).as_posix()
        except ValueError:
            return resolved_path.as_posix()

    def _to_abs_path(self, stored_path: str) -> Path:
        candidate = Path(stored_path)
        if candidate.is_absolute():
            return candidate
        return (self._cache_dir / candidate).resolve()

    def is_index_file(self, path: Path) -> bool:
        db_name = self._db_path.name
        name = path.name
        return name == db_name or name.startswith(f"{db_name}-")
