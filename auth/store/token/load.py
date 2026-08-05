"""Authentication token loading."""

from pathlib import Path

from ....storage.backend import build_folder_namespace


class MatrixAuthStoreTokenLoadMixin:
    """Load a complete authentication session from disk."""

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
                        source_desc = f"backend={backend}, namespace={build_folder_namespace(target_dir, Path(self.config.store_path))}"

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
                            self._save_token_to_backend(store, data)
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


__all__ = ["MatrixAuthStoreTokenLoadMixin"]
