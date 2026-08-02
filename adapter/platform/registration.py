"""AstrBot platform registration lifecycle helpers."""

from astrbot.api import logger


def _cleanup_platform_registration(adapter_name: str = "matrix") -> None:
    """清理之前的平台适配器注册（用于热重载）。"""
    try:
        from astrbot.core.platform.register import platform_cls_map, platform_registry

        if adapter_name in platform_cls_map:
            del platform_cls_map[adapter_name]
            logger.debug(f"已清理平台适配器 {adapter_name} 的类映射")

        to_remove = [pm for pm in platform_registry if pm.name == adapter_name]
        for pm in to_remove:
            platform_registry.remove(pm)
            logger.debug(f"已清理平台适配器 {adapter_name} 的注册元数据")

    except Exception as e:
        logger.debug(f"清理平台适配器注册时出错（可忽略）: {e}")


__all__ = ["_cleanup_platform_registration"]
