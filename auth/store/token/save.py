"""Authentication token saving."""

from pathlib import Path

from ....storage.backend import build_folder_namespace


class MatrixAuthStoreTokenSaveMixin:
    """Persist a complete authentication session."""

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
                self._save_token_to_backend(store, data)
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


__all__ = ["MatrixAuthStoreTokenSaveMixin"]
