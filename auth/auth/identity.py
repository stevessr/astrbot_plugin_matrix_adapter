"""Matrix authentication identity and callback state."""

from pathlib import Path

from astrbot.api import logger


class MatrixAuthIdentityMixin:
    """Initialize authentication state and expose identity helpers."""

    def __init__(self, client, config, token_store_path: str | Path | None = None):
        self.client = client
        self.config = config
        self.user_id = config.user_id
        # device_id 现在通过配置类的属性获取，会自动生成或从存储中恢复
        # 不再设置 self.device_id，直接使用 config.device_id 属性
        self.password = config.password
        self.access_token = config.access_token
        self.auth_method = config.auth_method
        self.device_name = config.device_name
        self.token_store_path = token_store_path
        self._config_needs_save = False
        self.login_info = {}

        # OAuth2 specific attributes
        # All OAuth2 configuration is auto-discovered from server
        self.refresh_token: str | None = getattr(config, "refresh_token", None)
        self.client_id: str | None = None
        self.client_secret: str | None = None
        self.oauth2_handler = None
        self._active_auth_webhook_handler = None
        self._device_id_rotated_for_reauth = False

    def _log(self, level, msg):
        extra = {"plugin_tag": "matrix", "short_levelname": level[:4].upper()}
        if level == "info":
            logger.info(msg, extra=extra)
        elif level == "error":
            logger.error(msg, extra=extra)

    @property
    def device_id(self) -> str:
        """获取设备 ID"""
        return self.config.device_id

    def _current_device_id_for_logging(self) -> str | None:
        try:
            return self.device_id
        except Exception:
            return getattr(self.config, "device_id", None)

    def _reset_device_id_for_reauth(self, reason: str) -> str | None:
        if self._device_id_rotated_for_reauth:
            return self._current_device_id_for_logging()

        reset_device_id = getattr(self.config, "reset_device_id", None)
        if not callable(reset_device_id):
            current_device_id = self._current_device_id_for_logging()
            self._log(
                "info",
                "Stored token invalid but config does not support regenerating "
                f"device_id, reusing {current_device_id!r} ({reason})",
            )
            self._device_id_rotated_for_reauth = True
            return current_device_id

        previous_device_id = self._current_device_id_for_logging()
        new_device_id = reset_device_id()
        if hasattr(self.client, "device_id"):
            try:
                self.client.device_id = new_device_id
            except Exception:
                pass

        self._log(
            "info",
            "Stored token invalid, regenerated Matrix device_id for re-auth: "
            f"{previous_device_id} -> {new_device_id} ({reason})",
        )
        self._device_id_rotated_for_reauth = True
        return new_device_id

    async def handle_webhook_callback(self, request):
        handler = self._active_auth_webhook_handler
        if handler and hasattr(handler, "handle_webhook_callback"):
            return await handler.handle_webhook_callback(request)
        self._log("info", "收到 Matrix 认证回调，但当前没有进行中的认证流程")
        return "Matrix authentication flow is not ready, please retry.", 503
