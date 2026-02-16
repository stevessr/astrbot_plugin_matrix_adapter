"""
Matrix auth token storage helpers.
"""

import json
from pathlib import Path

from ..plugin_config import get_plugin_config
from ..storage_backend import (
    MatrixFolderDataStore,
    StorageBackendConfig,
    build_folder_namespace,
)


class MatrixAuthStore:
    """Mixin providing token storage helpers."""

    def _get_token_store_path(self) -> str:
        """Get path for storing auth token."""
        if self.token_store_path:
            return self.token_store_path

        from ..storage_paths import MatrixStoragePaths

        if self.user_id and self.config.homeserver:
            auth_path = MatrixStoragePaths.get_auth_file_path(
                self.config.store_path, self.config.homeserver, self.user_id
            )
            MatrixStoragePaths.ensure_directory(auth_path)
            return str(auth_path)

        sanitized_user = (
            self.user_id.replace(":", "_").replace("@", "")
            if self.user_id
            else "unknown"
        )
        return str(Path("data") / f"matrix_auth_{sanitized_user}.json")

    @staticmethod
    def _auth_json_filename(_: str) -> str:
        return "auth.json"

    def _get_storage_backend(self) -> str:
        return self._get_storage_backend_config().backend

    def _get_storage_backend_config(self) -> StorageBackendConfig:
        return get_plugin_config().storage_backend_config

    def _get_user_storage_dir(self) -> Path | None:
        if not self.user_id or not self.config.homeserver:
            return None
        from ..storage_paths import MatrixStoragePaths

        return MatrixStoragePaths.get_user_storage_dir(
            self.config.store_path, self.config.homeserver, self.user_id
        )

    def _discover_single_user_storage_dir(self) -> Path | None:
        from ..storage_paths import MatrixStoragePaths

        base = Path(self.config.store_path)
        hs_dir = MatrixStoragePaths.sanitize_homeserver(self.config.homeserver)
        hs_path = base / hs_dir
        if hs_path.exists() and hs_path.is_dir():
            subdirs = [d for d in hs_path.iterdir() if d.is_dir()]
            if len(subdirs) == 1:
                return subdirs[0]
        return None

    def _build_auth_store(
        self, user_storage_dir: Path, storage_backend_config: StorageBackendConfig
    ) -> MatrixFolderDataStore:
        namespace = build_folder_namespace(user_storage_dir, Path(self.config.store_path))
        backend = storage_backend_config.backend
        try:
            return MatrixFolderDataStore(
                folder_path=user_storage_dir,
                namespace_key=namespace,
                backend=backend,
                json_filename_resolver=self._auth_json_filename,
                pgsql_dsn=storage_backend_config.pgsql_dsn,
                pgsql_schema=storage_backend_config.pgsql_schema,
                pgsql_table_prefix=storage_backend_config.pgsql_table_prefix,
            )
        except Exception as e:
            self._log("info", f"Auth store backend {backend} init failed, fallback json: {e}")
            return MatrixFolderDataStore(
                folder_path=user_storage_dir,
                namespace_key=namespace,
                backend="json",
                json_filename_resolver=self._auth_json_filename,
            )

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

        with open(path_obj, encoding="utf-8") as f:
            data = json.load(f)
        return data, path

    def _save_token_to_json_file(self, data: dict) -> str:
        path = self._get_token_store_path()
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def _save_token(self):
        """Save access token to disk."""
        if not self.access_token:
            return

        try:
            data = {
                "access_token": self.access_token,
                "device_id": self.device_id,
                "user_id": self.user_id,
                "home_server": self.config.homeserver,
            }
            if self.refresh_token:
                data["refresh_token"] = self.refresh_token

            if self.client_id:
                data["client_id"] = self.client_id
            if self.client_secret:
                data["client_secret"] = self.client_secret

            backend_config = self._get_storage_backend_config()
            backend = backend_config.backend
            user_storage_dir = self._get_user_storage_dir()
            if backend != "json" and user_storage_dir is not None:
                store = self._build_auth_store(user_storage_dir, backend_config)
                store.upsert("auth", data)
                self._log(
                    "info",
                    (
                        "Saved auth token "
                        f"(backend={backend}, namespace={build_folder_namespace(user_storage_dir, Path(self.config.store_path))})"
                    ),
                )
            else:
                path = self._save_token_to_json_file(data)
                self._log("info", f"Saved auth token to {path}")
        except Exception as e:
            self._log("error", f"Failed to save auth token: {e}")

    def _load_token(self) -> bool:
        """Load access token from disk."""
        try:
            backend_config = self._get_storage_backend_config()
            backend = backend_config.backend
            data = None
            source_desc = ""

            user_storage_dir = self._get_user_storage_dir()
            discovered_dir: Path | None = None
            if user_storage_dir is None and backend != "json":
                discovered_dir = self._discover_single_user_storage_dir()

            if backend != "json":
                target_dir = user_storage_dir or discovered_dir
                if target_dir is not None:
                    store = self._build_auth_store(target_dir, backend_config)
                    loaded = store.get("auth")
                    if isinstance(loaded, dict):
                        data = loaded
                        source_desc = (
                            f"backend={backend}, namespace={build_folder_namespace(target_dir, Path(self.config.store_path))}"
                        )

            if data is None:
                data, path = self._load_token_from_json_file()
                if data is None:
                    return False
                source_desc = path
                if backend != "json":
                    target_dir = user_storage_dir or discovered_dir
                    if target_dir is not None:
                        try:
                            store = self._build_auth_store(target_dir, backend_config)
                            store.upsert("auth", data)
                        except Exception as migrate_error:
                            self._log(
                                "info",
                                f"Failed to migrate auth token to {backend}: {migrate_error}",
                            )

            if data.get("home_server") != self.config.homeserver:
                self._log(
                    "info", "Stored token is for a different homeserver, ignoring"
                )
                return False

            self.access_token = data.get("access_token")
            device_id = data.get("device_id")

            stored_user_id = data.get("user_id")
            if stored_user_id and not self.user_id:
                self.user_id = stored_user_id
                self.config.user_id = stored_user_id
                self._log("info", f"Auto-detected user_id: {self.user_id}")

            if device_id:
                self.config.set_device_id(device_id)
            self.refresh_token = data.get("refresh_token")

            self.client_id = data.get("client_id")
            self.client_secret = data.get("client_secret")

            if self.access_token:
                self._log("info", f"Loaded auth token from {source_desc}")
                return True
            return False
        except Exception as e:
            self._log("error", f"Failed to load auth token: {e}")
            return False
