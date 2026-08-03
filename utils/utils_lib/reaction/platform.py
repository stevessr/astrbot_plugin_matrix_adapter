"""Matrix platform discovery helpers used by reaction utilities."""

from astrbot.api import logger


class MatrixUtilsReactionPlatformMixin:
    """Find Matrix platform, client, and E2EE instances."""

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
            for platform in MatrixUtilsReactionPlatformMixin.iter_platform_instances(
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

    @staticmethod
    def get_matrix_platform(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix 平台实例，优先匹配 platform_id。"""
        target_platform_id = str(platform_id or "")
        fallback_platform = None

        try:
            for platform in MatrixUtilsReactionPlatformMixin.iter_platform_instances(
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

    @staticmethod
    def get_matrix_client(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix 客户端实例。"""
        platform = MatrixUtilsReactionPlatformMixin.get_matrix_platform(
            context, platform_id, fallback_to_first=fallback_to_first
        )
        if platform is None:
            return None
        return getattr(platform, "client", None)

    @staticmethod
    def get_matrix_e2ee_manager(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix E2EE 管理器实例。"""
        platform = MatrixUtilsReactionPlatformMixin.get_matrix_platform(
            context, platform_id, fallback_to_first=fallback_to_first
        )
        if platform is None:
            return None
        return getattr(platform, "e2ee_manager", None)
