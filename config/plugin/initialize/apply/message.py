"""Plugin message-type, reply, typing, and read-receipt settings."""

from ....defaults import _normalize_bool, _normalize_message_type, _warn_config_coercion


class PluginConfigInitializationMessageMixin:
    """Apply message-type and interaction settings from the config dictionary."""

    def _initialize_message_settings(self, config: dict) -> None:
        # 消息类型配置
        self._force_message_type = _normalize_message_type(
            config.get("matrix_force_message_type"),
            config.get("matrix_force_private_message"),
        )
        raw_force_type = config.get("matrix_force_message_type")
        if raw_force_type is not None:
            normalized_force_type = (
                raw_force_type.strip().lower()
                if isinstance(raw_force_type, str)
                else raw_force_type
            )
            if normalized_force_type != self._force_message_type:
                _warn_config_coercion(
                    config_key="matrix_force_message_type",
                    raw_value=raw_force_type,
                    normalized_value=self._force_message_type,
                    reason="invalid or legacy message type value",
                )

        # 回复自适应配置
        self._adaptive_thread_reply = _normalize_bool(
            config.get("matrix_adaptive_thread_reply"), True
        )

        # 输入状态与已读回执配置
        self._send_typing = _normalize_bool(config.get("matrix_send_typing"), False)
        self._send_read_receipt = _normalize_bool(
            config.get("matrix_send_read_receipt"), True
        )
