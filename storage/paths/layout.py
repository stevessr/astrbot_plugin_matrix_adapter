"""Storage directory and file layout helpers."""

from pathlib import Path


class StoragePathLayoutMixin:
    @classmethod
    def get_user_storage_dir(
        cls, store_path: str | Path, homeserver: str, user_id: str
    ) -> Path:
        """获取用户的存储目录路径。"""
        base_path = Path(store_path)
        server_dir = cls.sanitize_homeserver(homeserver)
        user_dir = cls.sanitize_username(user_id)
        return base_path / server_dir / user_dir

    @classmethod
    def get_auth_file_path(
        cls,
        store_path: str | Path,
        homeserver: str,
        user_id: str,
        filename: str = "auth.json",
    ) -> Path:
        """获取认证文件的路径。"""
        return cls.get_user_storage_dir(store_path, homeserver, user_id) / filename

    @classmethod
    def get_sync_file_path(
        cls,
        store_path: str | Path,
        homeserver: str,
        user_id: str,
        filename: str = "sync.json",
    ) -> Path:
        """获取同步文件的路径。"""
        return cls.get_user_storage_dir(store_path, homeserver, user_id) / filename

    @classmethod
    def get_device_info_path(
        cls,
        store_path: str | Path,
        homeserver: str,
        user_id: str,
        filename: str = "device_info.json",
    ) -> Path:
        """获取设备信息文件的路径。"""
        return cls.get_user_storage_dir(store_path, homeserver, user_id) / filename

    @classmethod
    def ensure_directory(
        cls, file_path: str | Path, *, treat_as_file: bool | None = None
    ) -> Path:
        """确保文件的目录存在。"""
        path_obj = Path(file_path)
        if treat_as_file is None:
            treat_as_file = path_obj.suffix != ""
        target_dir = path_obj.parent if treat_as_file else path_obj
        target_dir.mkdir(parents=True, exist_ok=True)
        return path_obj


__all__ = ["StoragePathLayoutMixin"]
