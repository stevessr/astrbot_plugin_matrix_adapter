"""Own-user echo suppression and device takeover handling."""

from astrbot.api import logger

from .....constants import (
    M_KEY_VERIFICATION_ACCEPT,
    M_KEY_VERIFICATION_CANCEL,
    M_KEY_VERIFICATION_DONE,
    M_KEY_VERIFICATION_KEY,
    M_KEY_VERIFICATION_MAC,
    M_KEY_VERIFICATION_REQUEST,
)


class SASVerificationRoomEventDispatchOwnMixin:
    """处理来自本用户事件的回显跳过与设备接管。"""

    async def _handle_own_user_room_event(
        self,
        sender: str,
        event_type: str,
        content: dict,
        transaction_id: str,
    ) -> bool | None:
        from_device = content.get("from_device")

        # Skip our own key/mac/done/accept events (these are echoes of what we sent)
        # We only need to process these events from the OTHER party
        if event_type in (
            M_KEY_VERIFICATION_KEY,
            M_KEY_VERIFICATION_MAC,
            M_KEY_VERIFICATION_DONE,
            M_KEY_VERIFICATION_ACCEPT,
        ):
            logger.debug(f"[E2EE-Verify] 跳过自己发送的事件：{event_type}")
            return True  # Ignore our own echoed events

        if from_device and from_device != self.device_id:
            # 只有当事件明确表明另一个设备正在进行交互时（例如 ready/start/accept），我们才退出
            # 忽略 request 事件（因为那是发起请求，不代表接管）
            if event_type not in (
                M_KEY_VERIFICATION_REQUEST,
                M_KEY_VERIFICATION_CANCEL,
            ):
                logger.info(
                    "[E2EE-Verify] 检测到其他设备 "
                    f"{from_device} 正在处理验证 txn={(transaction_id or '')[:8]}...，本设备将静默退出"
                )
                # 标记会话为已由其他设备处理，停止本地处理
                if transaction_id in self._sessions:
                    self._sessions[transaction_id]["state"] = "handled_by_other_device"
                return True  # 已处理（忽略）

        return None
