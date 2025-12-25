from astrbot.api.star import Context, Star, register


@register(
    "astrbot_plugin_matrix_adapter",
    "stevessr",
    "Matrix 协议适配器，支持端到端加密、消息线程等功能",
    "0.1.0",
)
class MatrixPlugin(Star):
    def __init__(self, context: Context, config=None):
        super().__init__(context, config)

        # 初始化插件级别配置（目录路径等）
        try:
            from .plugin_config import init_plugin_config

            # 从 AstrBot 配置中获取插件配置
            plugin_config = (
                self.context.get_config()
                .get("plugin_config", {})
                .get("astrbot_plugin_matrix_adapter", {})
            )
            init_plugin_config(plugin_config)
        except Exception:
            pass  # 配置初始化失败时使用默认值

        try:
            from .matrix_adapter import _inject_astrbot_field_metadata
            _inject_astrbot_field_metadata()
            from .matrix_adapter import MatrixPlatformAdapter  # noqa
            from .matrix_event import MatrixPlatformEvent  # noqa
        except ImportError as e:
            from astrbot.api import logger

            logger.error(f"导入 Matrix Adapter 失败，请检查依赖是否安装：{e}")
            # 抛出异常，避免处于"已加载但不可用"的不一致状态
            raise
