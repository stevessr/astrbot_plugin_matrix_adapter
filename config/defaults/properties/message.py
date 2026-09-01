"""Default-backed configuration properties: messaging."""


class PluginConfigDefaultsMessageMixin:
    """消息处理相关的默认配置属性。"""

    @property
    def force_message_type(self) -> str:
        """强制消息类型（auto / private / group / stalk）"""
        return self._force_message_type

    @property
    def adaptive_thread_reply(self) -> bool:
        """回复自适应：入站消息在消息列内时，回复也留在同一消息列"""
        return self._adaptive_thread_reply

    @property
    def send_typing(self) -> bool:
        """是否发送「正在输入」（typing）状态"""
        return self._send_typing

    @property
    def read_receipt_type(self) -> str:
        """已读回执模式：none / private / public / batch。"""
        return self._read_receipt_type

    @property
    def read_receipt_batch_interval_ms(self) -> int:
        """批次已读固定窗口长度（毫秒）。"""
        return self._read_receipt_batch_interval_ms

    @property
    def send_read_receipt(self) -> bool:
        """兼容旧调用：除 none 外均视为启用已读回执。"""
        return self._read_receipt_type != "none"

    @property
    def force_private_message(self) -> bool:
        """兼容旧配置：是否将所有消息强制视为私聊"""
        return self._force_message_type == "private"
