"""Plugin configuration and platform registration lifecycle."""

from astrbot.api import logger


def initialize_plugin(config=None) -> None:
    """Initialize shared configuration and register Matrix platform metadata."""
    try:
        from ...config.plugin import get_plugin_config, init_plugin_config

        # 使用传入的 config 参数（AstrBot 从 astrbot_plugin_matrix_adapter_config.json 加载）
        plugin_config = config if isinstance(config, dict) else {}
        init_plugin_config(plugin_config)
        plugin_cfg = get_plugin_config()
        logger.debug(
            f"Matrix 插件配置已加载：force_message_type={plugin_cfg.force_message_type}"
        )
    except Exception as e:
        logger.error(
            f"Matrix 插件配置初始化失败，将使用默认配置：{e}",
            extra={"plugin_tag": "matrix", "short_levelname": "ERROR"},
        )

    # 在导入 MatrixPlatformAdapter 之前注入字段元数据
    # 这样 @register_platform_adapter 装饰器执行时就能获取到正确的元数据
    try:
        from ..platform import _inject_astrbot_field_metadata

        _inject_astrbot_field_metadata()
        logger.debug("✅ Matrix 字段元数据已注入")
    except Exception as e:
        logger.error(f"❌ 注入 Matrix 字段元数据失败：{e}")

    try:
        from ..platform import MatrixPlatformAdapter  # noqa: F401
    except ImportError as e:
        logger.error(f"导入 Matrix Adapter 失败，请检查依赖是否安装：{e}")
        # 抛出异常，避免处于"已加载但不可用"的不一致状态
        raise


__all__ = ["initialize_plugin"]
