"""Matrix platform client and E2EE access helpers."""

from .selection import MatrixUtilsReactionPlatformSelectionMixin


class MatrixUtilsReactionPlatformAccessMixin:
    """Access Matrix client and E2EE manager from a platform."""

    @staticmethod
    def get_matrix_client(
        context, platform_id: str = "", fallback_to_first: bool = True
    ):
        """获取 Matrix 客户端实例。"""
        platform = MatrixUtilsReactionPlatformSelectionMixin.get_matrix_platform(
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
        platform = MatrixUtilsReactionPlatformSelectionMixin.get_matrix_platform(
            context, platform_id, fallback_to_first=fallback_to_first
        )
        if platform is None:
            return None
        return getattr(platform, "e2ee_manager", None)


__all__ = ["MatrixUtilsReactionPlatformAccessMixin"]
