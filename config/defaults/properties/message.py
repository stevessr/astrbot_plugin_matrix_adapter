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
    def send_read_receipt(self) -> bool:
        """是否在消息处理完成后发送已读回执"""
        return self._send_read_receipt

    @property
    def force_private_message(self) -> bool:
        """兼容旧配置：是否将所有消息强制视为私聊"""
        return self._force_message_type == "private"
