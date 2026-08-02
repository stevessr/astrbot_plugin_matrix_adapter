"""JSON token file persistence and atomic file operations."""

import json
import os
import threading
import time
from pathlib import Path


class MatrixAuthStoreFileMixin:
    """Read and write token files with secure permissions."""

    def _load_token_from_json_file(self) -> tuple[dict | None, str]:
        path = self._get_token_store_path()

        if not self.user_id:
            discovered_dir = self._discover_single_user_storage_dir()
            if discovered_dir is not None:
                discovered_path = discovered_dir / "auth.json"
                if discovered_path.exists():
                    path = str(discovered_path)
                    self._log("info", f"Auto-discovered auth file: {path}")

        path_obj = Path(path)
        if not path_obj.exists():
            return None, path
        self._harden_path_mode(path_obj, 0o600)

        with open(path_obj, encoding="utf-8") as f:
            data = json.load(f)
        return data, path

    @staticmethod
    def _harden_path_mode(path: Path, mode: int) -> None:
        try:
            path.chmod(mode)
        except OSError:
            # Ignore platforms/filesystems that don't support POSIX chmod semantics.
            pass

    def _write_json_token_atomically(self, path_obj: Path, data: dict) -> None:
        temp_path = path_obj.with_name(
            f".{path_obj.name}.{os.getpid()}.{time.time_ns()}.tmp"
        )
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            self._harden_path_mode(temp_path, 0o600)
            temp_path.replace(path_obj)
            self._harden_path_mode(path_obj, 0o600)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _save_token_to_json_file(self, data: dict) -> str:
        path = self._get_token_store_path()
        path_obj = Path(path)
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        self._harden_path_mode(path_obj.parent, 0o700)
        with self._token_file_save_lock:
            self._write_json_token_atomically(path_obj, data)
        return str(path_obj)

    _token_file_save_lock = threading.Lock()
