from astrbot.api.star import Context, Star


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

        # 强制预清理：在导入适配器前，无条件删除既有 matrix 注册，确保干净状态
        try:
            from astrbot.api import logger

            modules = []
            try:
                import astrbot.api.platform.register as _api_reg

                modules.append(_api_reg)
            except Exception:
                pass
            try:
                import astrbot.core.platform.register as _core_reg

                modules.append(_core_reg)
            except Exception:
                pass
            for _m in modules:
                _map = getattr(_m, "platform_cls_map", None)
                try:
                    if _map is not None and ("matrix" in _map):
                        del _map["matrix"]
                        try:
                            logger.debug("强制预清理：已移除 matrix 既有注册。")
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass

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
