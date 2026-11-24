"""Core SAS verification manager composition."""

from pathlib import Path
from typing import Any, Literal

from ....config.plugin import get_plugin_config
from ...device_store import DeviceStore
from .. import SASVerificationFlowMixin
from ..display import SASVerificationDisplayMixin
from ..event import SASVerificationEventMixin
from ..manual_notify import SASVerificationManualNotifyMixin
from ..send_device import SASVerificationSendDeviceMixin
from ..send_room import SASVerificationSendRoomMixin
from .approval import SASVerificationApprovalMixin
from .qr import SASVerificationQRMixin


class SASVerification(
    SASVerificationEventMixin,
    SASVerificationFlowMixin,
    SASVerificationDisplayMixin,
    SASVerificationManualNotifyMixin,
    SASVerificationSendDeviceMixin,
    SASVerificationSendRoomMixin,
    SASVerificationQRMixin,
    SASVerificationApprovalMixin,
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
        *,
        namespace_key: str | None = None,
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
        self.admin_notify_room_ids: list[str] = []

        # 活跃的验证会话：transaction_id -> session_data
        self._sessions: dict[str, dict[str, Any]] = {}
        # Stable Matrix verification transactions have a hard 10-minute lifetime
        # and a 10-minute idle timeout. The actual watcher is created lazily when
        # a session is initialized or first used inside a running event loop.
        self._verification_timeout_enabled = True
        self._verification_timeout_tasks: dict[str, Any] = {}
        self.storage_backend_config = get_plugin_config().storage_backend_config
        self.device_store = DeviceStore(
            store_path,
            namespace_key=namespace_key,
        )

    def initiate_verification(self, transaction_id: str, to_user: str, to_device: str):
        """记录主动发起的验证会话"""
        session = {
            "sender": to_user,  # 目标用户
            "their_device": to_device,
            "state": "request_sent",
            "we_started_it": True,  # 标记我们发起了 request
            "we_are_initiator": True,  # 通常发起 request 的也会发 start，所以也是 SAS initiator
        }
        self._sessions[transaction_id] = session
        self._initialize_verification_session_lifecycle(session, transaction_id)

    def set_admin_notify_room(self, room_id: str | None):
        """设置管理员验证通知房间（用于手动 SAS 验证提示）。"""
        normalized_room = str(room_id or "").strip()
        self.admin_notify_room_id = normalized_room or None


__all__ = ["SASVerification"]
