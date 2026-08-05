"""Matrix adapter authentication and startup operations."""

from astrbot.api import logger

from .auth import _startup_auth
from .e2ee import _startup_e2ee
from .identity import _startup_sync_identity
from .media import _startup_media_config, _startup_presence
from .tasks import _startup_cache_gc


class MatrixAdapterRuntimeStartupMixin:
    """Authenticate and start the Matrix adapter runtime."""

    async def run(self):
        try:
            await _startup_auth(self)

            await _startup_sync_identity(self)

            await _startup_media_config(self)

            await _startup_presence(self)

            await _startup_e2ee(self)

            await _startup_cache_gc(self)

            logger.info(
                f"Matrix 平台适配器正在为 {self._matrix_config.user_id} 在 {self._matrix_config.homeserver} 上运行"
            )
            if getattr(self, "runtime_state", None):
                self.runtime_state.mark_lifecycle("running")
                self.runtime_state.mark_sync_started()
            await self.sync_manager.sync_forever()
        except KeyboardInterrupt:
            logger.info("Matrix 适配器收到关闭信号")
            raise
        except Exception as e:
            if getattr(self, "runtime_state", None):
                category = (
                    "auth" if self.runtime_state.auth_state != "ready" else "sync"
                )
                self.runtime_state.record_error(category, str(e))
                self.runtime_state.mark_lifecycle("error")
            logger.error(f"Matrix 适配器错误：{e}")
            logger.error("Matrix 适配器启动失败。请检查配置并查看上方详细错误信息。")
            raise


# Preserve direct method attributes exposed by the former startup mixin.
for _method in (
    _startup_auth,
    _startup_cache_gc,
    _startup_e2ee,
    _startup_media_config,
    _startup_presence,
    _startup_sync_identity,
):
    setattr(MatrixAdapterRuntimeStartupMixin, _method.__name__, _method)
