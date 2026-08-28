"""Plugin message-type, reply, typing, and read-receipt settings."""

from ....defaults import (
    _normalize_bool,
    _normalize_message_type,
    _normalize_non_negative_int,
    _warn_config_coercion,
)

_READ_RECEIPT_TYPES = {"none", "private", "public", "batch"}
_READ_RECEIPT_TYPE_ALIASES = {
    "off": "none",
    "false": "none",
    "disabled": "none",
    "m.read.private": "private",
    "m.read": "public",
    "batched": "batch",
}
_DEFAULT_READ_RECEIPT_BATCH_INTERVAL_MS = 2000


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

        # 输入状态
        self._send_typing = _normalize_bool(config.get("matrix_send_typing"), False)

        # 已读回执类型。优先使用新配置；旧 bool 配置仍保留兼容：
        # true -> public，false -> none。
        raw_receipt_type = config.get("matrix_read_receipt_type")
        if raw_receipt_type is None:
            legacy_enabled = _normalize_bool(
                config.get("matrix_send_read_receipt"), True
            )
            self._read_receipt_type = "public" if legacy_enabled else "none"
        else:
            normalized_receipt_type = (
                raw_receipt_type.strip().lower()
                if isinstance(raw_receipt_type, str)
                else ""
            )
            normalized_receipt_type = _READ_RECEIPT_TYPE_ALIASES.get(
                normalized_receipt_type,
                normalized_receipt_type,
            )
            if normalized_receipt_type not in _READ_RECEIPT_TYPES:
                _warn_config_coercion(
                    config_key="matrix_read_receipt_type",
                    raw_value=raw_receipt_type,
                    normalized_value="public",
                    reason="invalid read receipt type",
                )
                normalized_receipt_type = "public"
            self._read_receipt_type = normalized_receipt_type

        self._read_receipt_batch_interval_ms = _normalize_non_negative_int(
            config.get("matrix_read_receipt_batch_interval_ms"),
            _DEFAULT_READ_RECEIPT_BATCH_INTERVAL_MS,
            min_value=100,
            config_key="matrix_read_receipt_batch_interval_ms",
        )
