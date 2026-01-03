"""
Matrix auth token storage helpers.
"""

import json
from pathlib import Path


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

    def _save_token(self):
        """Save access token to disk."""
        if not self.access_token:
            return

        try:
            path = self._get_token_store_path()
            Path(path).parent.mkdir(parents=True, exist_ok=True)

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

            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            self._log("info", f"Saved auth token to {path}")
        except Exception as e:
            self._log("error", f"Failed to save auth token: {e}")

    def _load_token(self) -> bool:
        """Load access token from disk."""
        try:
            path = self._get_token_store_path()

            if not self.user_id:
                from ..storage_paths import MatrixStoragePaths

                base = Path(self.config.store_path)
                hs_dir = MatrixStoragePaths.sanitize_homeserver(self.config.homeserver)
                hs_path = base / hs_dir

                if hs_path.exists() and hs_path.is_dir():
                    subdirs = [d for d in hs_path.iterdir() if d.is_dir()]
                    if len(subdirs) == 1:
                        discovered_path = subdirs[0] / "auth.json"
                        if discovered_path.exists():
                            path = str(discovered_path)
                            self._log("info", f"Auto-discovered auth file: {path}")

            if not Path(path).exists():
                return False

            with open(path) as f:
                data = json.load(f)

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
                self._log("info", f"Loaded auth token from {path}")
                return True
            return False
        except Exception as e:
            self._log("error", f"Failed to load auth token: {e}")
            return False
