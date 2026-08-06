"""Platform instance iteration helpers."""

from astrbot.api import logger


class MatrixUtilsReactionPlatformInstancesMixin:
    """Iterate Matrix platform instances."""

    @staticmethod
    def iter_platform_instances(context) -> list:
        """获取平台实例列表（兼容 get_insts / platform_insts）。"""
        platform_manager = getattr(context, "platform_manager", None)
        if platform_manager is None:
            return []

        get_insts = getattr(platform_manager, "get_insts", None)
        if callable(get_insts):
            try:
                platforms = get_insts()
                if isinstance(platforms, list):
                    return platforms
                return list(platforms)
            except Exception as e:
                logger.debug(f"通过 get_insts 获取平台实例失败：{e}")

        platforms = getattr(platform_manager, "platform_insts", None)
        if isinstance(platforms, list):
            return platforms
        return []

    @staticmethod
    def list_matrix_platform_ids(context) -> list[str]:
        """列出所有 Matrix 适配器平台 ID。"""
        platform_ids: list[str] = []
        try:
            for (
                platform
            ) in MatrixUtilsReactionPlatformInstancesMixin.iter_platform_instances(
                context
            ):
                try:
                    meta = platform.meta()
                except Exception:
                    continue

                meta_name = str(getattr(meta, "name", "") or "").strip().lower()
                if meta_name != "matrix":
                    continue

                meta_id = str(getattr(meta, "id", "") or "").strip()
                if meta_id:
                    platform_ids.append(meta_id)
        except Exception as e:
            logger.debug(f"列出 Matrix 平台实例失败：{e}")

        return platform_ids


__all__ = ["MatrixUtilsReactionPlatformInstancesMixin"]
