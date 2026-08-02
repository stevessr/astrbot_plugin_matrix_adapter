"""
Matrix 消息发送组件
"""

from ..room_messaging import SenderRoomMessagingMixin
from ..sender_lib import SenderMediaMixin, SenderRoomMixin
from .moderation import SenderModerationMixin
from .presence import SenderPresenceMixin


class MatrixSender(
    SenderRoomMessagingMixin,
    SenderMediaMixin,
    SenderRoomMixin,
    SenderModerationMixin,
    SenderPresenceMixin,
):
    def __init__(self, client, e2ee_manager=None, *, use_notice: bool = False):
        self.client = client
        self.e2ee_manager = e2ee_manager
        self.use_notice = bool(use_notice)

    @staticmethod
    def _now_ms() -> int:
        import time

        return int(time.time() * 1000)
