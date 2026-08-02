"""Authentication token storage path discovery."""

from pathlib import Path


class MatrixAuthStorePathsMixin:
    """Resolve token files and user storage directories."""

    def _get_token_store_path(self) -> str:
        """Get path for storing auth token."""
        if self.token_store_path:
            return self.token_store_path

        from ...storage.paths import MatrixStoragePaths

        if self.user_id and self.config.homeserver:
            auth_path = MatrixStoragePaths.get_auth_file_path(
                self.config.store_path, self.config.homeserver, self.user_id
            )
            MatrixStoragePaths.ensure_directory(auth_path, treat_as_file=True)
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

    def _get_user_storage_dir(self) -> Path | None:
        if not self.user_id or not self.config.homeserver:
            return None
        from ...storage.paths import MatrixStoragePaths

        return MatrixStoragePaths.get_user_storage_dir(
            self.config.store_path, self.config.homeserver, self.user_id
        )

    def _discover_single_user_storage_dir(self) -> Path | None:
        from ...storage.paths import MatrixStoragePaths

        base = Path(self.config.store_path)
        hs_dir = MatrixStoragePaths.sanitize_homeserver(self.config.homeserver)
        hs_path = base / hs_dir
        if hs_path.exists() and hs_path.is_dir():
            try:
                subdirs = sorted((d for d in hs_path.iterdir() if d.is_dir()), key=str)
            except OSError:
                return None
            auth_json_dirs = [d for d in subdirs if (d / "auth.json").exists()]
            if len(auth_json_dirs) == 1:
                return auth_json_dirs[0]
            if len(subdirs) == 1:
                return subdirs[0]
        return None
