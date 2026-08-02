from __future__ import annotations

from astrbot.api import logger

from ....constants import M_ROOM_MESSAGE
from ....sender.events.common import send_content


class SASVerificationManualNotifySendingMixin:
    async def _send_manual_verification_notice(
        self,
        room_id: str,
        message: str,
        transaction_id: str,
    ) -> bool:
        is_encrypted_room = False
        try:
            is_encrypted_room = await self.client.is_room_encrypted(room_id)
            logger.debug(
                "[E2EE-Verify] 手动通知房间状态："
                f"room={room_id} encrypted={is_encrypted_room} "
                f"txn={self._mask_txn_id(transaction_id)}"
            )
        except Exception as e:
            logger.debug(
                "[E2EE-Verify] 获取房间加密状态失败，按未加密处理："
                f"room={room_id} err={e}"
            )

        await send_content(
            client=self.client,
            content={"msgtype": "m.text", "body": message},
            room_id=room_id,
            reply_to=None,
            thread_root=None,
            use_thread=False,
            is_encrypted_room=is_encrypted_room,
            e2ee_manager=getattr(self, "e2ee_manager", None),
            msg_type=M_ROOM_MESSAGE,
        )
        return True

    async def _notify_admin_rooms_for_verification(
        self,
        message: str,
        transaction_id: str,
    ) -> int:
        notify_rooms = self.get_admin_notify_rooms()
        if not notify_rooms:
            logger.debug("[E2EE-Verify] 未配置手动验证通知房间，跳过通知")
            return 0

        sent_count = 0
        for room_id in notify_rooms:
            try:
                if await self._send_manual_verification_notice(
                    room_id,
                    message,
                    transaction_id,
                ):
                    sent_count += 1
            except Exception as e:
                logger.warning(
                    "[E2EE-Verify] 手动验证通知发送失败："
                    f"room={room_id} txn={self._mask_txn_id(transaction_id)} err={e}"
                )

        return sent_count
