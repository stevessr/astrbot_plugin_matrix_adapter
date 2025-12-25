"""
Matrix 存储路径工具
提供统一的存储路径生成功能
"""

import re
from pathlib import Path


class MatrixStoragePaths:
    """
    Matrix 存储路径管理器

    提供统一的路径生成逻辑，确保所有模块使用一致的存储结构：
    matrix_store_path/homeserver/username/
    """

    @staticmethod
    def sanitize_homeserver(homeserver: str) -> str:
        """
        清理 homeserver URL 为目录名

        Args:
            homeserver: Matrix 服务器 URL

        Returns:
            可用作目录名的服务器标识
        """
        # 移除协议前缀
        homeserver = homeserver.replace("https://", "").replace("http://", "")

        # 移除末尾的斜杠
        homeserver = homeserver.rstrip("/")

        # 替换特殊字符
        homeserver = re.sub(r"[^\w\-\.]", "_", homeserver)

        return homeserver

    @staticmethod
    def sanitize_username(user_id: str) -> str:
        """
        清理用户 ID 为目录名

        Args:
            user_id: Matrix 用户 ID

        Returns:
            可用作目录名的用户标识
        """
        # 移除 @ 和替换特殊字符
        username = user_id.replace("@", "").replace(":", "_")
        username = re.sub(r"[^\w\-\.]", "_", username)

        return username

    @classmethod
    def get_user_storage_dir(
        cls, store_path: str, homeserver: str, user_id: str
    ) -> Path:
        """
        获取用户的存储目录路径

        Args:
            store_path: 基础存储路径
            homeserver: Matrix 服务器 URL
            user_id: Matrix 用户 ID

        Returns:
            用户存储目录的 Path 对象
        """
        base_path = Path(store_path)

        # 清理 homeserver 和 user_id
        server_dir = cls.sanitize_homeserver(homeserver)
        user_dir = cls.sanitize_username(user_id)

        # 构建完整路径
        user_storage_dir = base_path / server_dir / user_dir

        return user_storage_dir

    @classmethod
    def get_auth_file_path(
        cls, store_path: str, homeserver: str, user_id: str, filename: str = "auth.json"
    ) -> Path:
        """
        获取认证文件的路径

        Args:
            store_path: 基础存储路径
            homeserver: Matrix 服务器 URL
            user_id: Matrix 用户 ID
            filename: 文件名

        Returns:
            认证文件的 Path 对象
        """
        user_dir = cls.get_user_storage_dir(store_path, homeserver, user_id)
        return user_dir / filename

    @classmethod
    def get_sync_file_path(
        cls, store_path: str, homeserver: str, user_id: str, filename: str = "sync.json"
    ) -> Path:
        """
        获取同步文件的路径

        Args:
            store_path: 基础存储路径
            homeserver: Matrix 服务器 URL
            user_id: Matrix 用户 ID
            filename: 文件名

        Returns:
            同步文件的 Path 对象
        """
        user_dir = cls.get_user_storage_dir(store_path, homeserver, user_id)
        return user_dir / filename

    @classmethod
    def get_device_info_path(
        cls,
        store_path: str,
        homeserver: str,
        user_id: str,
        filename: str = "device_info.json",
    ) -> Path:
        """
        获取设备信息文件的路径

        Args:
            store_path: 基础存储路径
            homeserver: Matrix 服务器 URL
            user_id: Matrix 用户 ID
            filename: 文件名

        Returns:
            设备信息文件的 Path 对象
        """
        user_dir = cls.get_user_storage_dir(store_path, homeserver, user_id)
        return user_dir / filename

    @classmethod
    def ensure_directory(cls, file_path: Path) -> Path:
        """
        确保文件的目录存在

        Args:
            file_path: 文件路径

        Returns:
            文件路径（确保目录已创建）
        """
        file_path.parent.mkdir(parents=True, exist_ok=True)
        return file_path

    @staticmethod
    def migrate_old_paths(
        old_base_path: str, new_base_path: str, homeserver: str, user_id: str
    ) -> bool:
        """
        迁移旧的存储路径到新的路径结构

        Args:
            old_base_path: 旧的基础存储路径
            new_base_path: 新的基础存储路径
            homeserver: Matrix 服务器 URL
            user_id: Matrix 用户 ID

        Returns:
            是否成功迁移
        """
        try:
            # 旧的用户目录（仅基于用户名）
            sanitized_user = user_id.replace(":", "_").replace("@", "")
            old_user_dir = Path(old_base_path) / sanitized_user

            # 新的用户目录
            new_user_dir = MatrixStoragePaths.get_user_storage_dir(
                new_base_path, homeserver, user_id
            )

            # 如果旧目录存在且新目录不存在，进行迁移
            if old_user_dir.exists() and not new_user_dir.exists():
                import shutil

                new_user_dir.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old_user_dir), str(new_user_dir))

                from astrbot.api import logger

                logger.info(
                    f"已迁移 Matrix 存储路径：{old_user_dir} -> {new_user_dir}",
                    extra={"plugin_tag": "matrix", "short_levelname": "INFO"},
                )
                return True

        except Exception as e:
            from astrbot.api import logger

            logger.error(
                f"迁移 Matrix 存储路径失败：{e}",
                extra={"plugin_tag": "matrix", "short_levelname": "ERRO"},
            )

        return False
