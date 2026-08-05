"""Authentication stage of the Matrix adapter startup."""

from astrbot.api import logger


async def _startup_auth(self) -> None:
    if getattr(self, "runtime_state", None):
        self.runtime_state.mark_lifecycle("starting")
        self.runtime_state.mark_auth_started()
    save_config = getattr(self, "_save_config", None)
    if callable(save_config):
        await save_config()

    if getattr(self, "unified_webhook", None) and self.unified_webhook():
        webhook_uuid = str(self.config.get("webhook_uuid") or "").strip()
        if webhook_uuid:
            logger.info(
                f"Matrix 认证回调将复用 AstrBot Webhook: {self._matrix_config.auth_callback_url}"
            )
            try:
                from astrbot.core.utils.webhook_utils import log_webhook_info

                log_webhook_info(f"{self.meta().id}(Matrix Auth)", webhook_uuid)
            except Exception as e:
                logger.debug(f"打印 Matrix Webhook 信息失败：{e}")

    await self.auth.login()
    if getattr(self, "runtime_state", None):
        self.runtime_state.mark_auth_ok()
    persist_auth_config = getattr(self, "_persist_auth_config_if_needed", None)
    if callable(persist_auth_config):
        await persist_auth_config()
