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
