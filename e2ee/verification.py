"""
SAS Verification - Matrix 设备验证流程

实现 SAS (Short Authentication String) 验证协议。
使用 vodozemac 提供的真正 X25519 密钥交换和 HKDF。
支持 auto_accept / auto_reject / manual 三种模式。
所有模式都会打印详细的验证日志。
"""

from pathlib import Path
from typing import Any, Literal

from .device_store import DeviceStore
from .verification_handlers_display import SASVerificationDisplayMixin
from .verification_handlers_event import SASVerificationEventMixin
from .verification_handlers_flow import SASVerificationFlowMixin
from .verification_send_device import SASVerificationSendDeviceMixin
from .verification_send_room import SASVerificationSendRoomMixin


class SASVerification(
    SASVerificationEventMixin,
    SASVerificationFlowMixin,
    SASVerificationDisplayMixin,
    SASVerificationSendDeviceMixin,
    SASVerificationSendRoomMixin,
):
    """
    SAS 验证流程管理器

    使用 vodozemac 提供的真正密码学实现
    """

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        olm_machine,
        store_path: Path,
        auto_verify_mode: Literal[
            "auto_accept", "auto_reject", "manual"
        ] = "auto_accept",
        trust_on_first_use: bool = False,
    ):
        self.client = client
        self.user_id = user_id
        self.device_id = device_id
        self.olm = olm_machine
        self.auto_verify_mode = auto_verify_mode
        self.trust_on_first_use = trust_on_first_use
        self.admin_notify_room_id: str | None = None

        # 活跃的验证会话：transaction_id -> session_data
        self._sessions: dict[str, dict[str, Any]] = {}
        self.device_store = DeviceStore(store_path)

    def initiate_verification(self, transaction_id: str, to_user: str, to_device: str):
        """记录主动发起的验证会话"""
        self._sessions[transaction_id] = {
            "sender": to_user,  # 目标用户
            "their_device": to_device,
            "state": "request_sent",
            "we_started_it": True,  # 标记我们发起了 request
            "we_are_initiator": True,  # 通常发起 request 的也会发 start，所以也是 SAS initiator
        }

    def set_admin_notify_room(self, room_id: str | None):
        """设置管理员验证通知房间（用于手动 SAS 验证提示）。"""
        self.admin_notify_room_id = room_id

    async def approve_device(self, device_id: str) -> tuple[bool, str]:
        """手动确认某个设备的 SAS 验证（发送 MAC 与 DONE）。"""
        candidates: list[tuple[str, dict[str, Any]]] = []
        for txn_id, session in self._sessions.items():
            if session.get("from_device") == device_id or session.get("their_device") == device_id:
                candidates.append((txn_id, session))

        if not candidates:
            return False, f"未找到设备 {device_id} 的待验证会话"

        # 优先选择已完成密钥交换的会话
        txn_id, session = candidates[0]
        for tid, s in candidates:
            if s.get("sas_emojis") or s.get("sas_decimals"):
                txn_id, session = tid, s
                break

        sender = session.get("sender", "")
        target_device = session.get("from_device") or session.get("their_device") or device_id
        if not sender or not target_device:
            return False, "会话信息不完整，无法发送验证消息"

        is_in_room = session.get("is_in_room", False)
        room_id = session.get("room_id")

        if not session.get("sas_emojis") and not session.get("sas_decimals"):
            return False, "SAS 尚未就绪，请稍后再试"

        try:
            if not session.get("mac_sent"):
                session["mac_sent"] = True
                if is_in_room and room_id:
                    await self._send_in_room_mac(room_id, txn_id, session)
                else:
                    await self._send_mac(sender, target_device, txn_id, session)
            if not session.get("done_sent"):
                session["done_sent"] = True
                if is_in_room and room_id:
                    await self._send_in_room_done(room_id, txn_id)
                else:
                    await self._send_done(sender, target_device, txn_id)
        except Exception as e:
            return False, f"发送验证消息失败：{e}"

        return True, f"已发送验证确认（device_id={device_id}）"
