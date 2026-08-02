"""Legacy storage path migration helpers."""

from pathlib import Path


class StoragePathMigrationMixin:
    @staticmethod
    def migrate_old_paths(
        old_base_path: str, new_base_path: str, homeserver: str, user_id: str
    ) -> bool:
        """迁移旧的存储路径到新的路径结构。"""
        try:
            sanitized_user = user_id.replace(":", "_").replace("@", "")
            old_user_dir = Path(old_base_path) / sanitized_user

            from . import MatrixStoragePaths

            new_user_dir = MatrixStoragePaths.get_user_storage_dir(
                new_base_path, homeserver, user_id
            )

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


__all__ = ["StoragePathMigrationMixin"]
