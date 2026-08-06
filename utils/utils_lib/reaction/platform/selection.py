"""Matrix platform selection helpers."""

from astrbot.api import logger

from .instances import MatrixUtilsReactionPlatformInstancesMixin


class MatrixUtilsReactionPlatformSelectionMixin:
    """Select a Matrix platform by ID."""

    @staticmethod
    def get_matrix_platform(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix 平台实例，优先匹配 platform_id。"""
        target_platform_id = str(platform_id or "")
        fallback_platform = None

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

                if fallback_platform is None:
                    fallback_platform = platform

                meta_id = str(getattr(meta, "id", "") or "")
                if target_platform_id and meta_id == target_platform_id:
                    return platform
        except Exception as e:
            logger.debug(f"获取 Matrix 平台实例失败：{e}")

        if fallback_to_first:
            return fallback_platform
        return None


__all__ = ["MatrixUtilsReactionPlatformSelectionMixin"]
