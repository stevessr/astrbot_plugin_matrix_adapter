from __future__ import annotations

from astrbot.api import logger

from ..sender.handlers.common import send_content


class SASVerificationManualNotifyMixin:
    @staticmethod
    def _mask_txn_id(value: str | None) -> str:
        if not isinstance(value, str) or not value:
            return "<empty>"
        normalized = value.strip()
        if len(normalized) <= 8:
            return "***"
        return f"{normalized[:8]}..."

    def set_admin_notify_rooms(self, room_ids: list[str] | None):
        """设置管理员验证通知房间列表（用于手动 SAS 验证提示）。"""
        normalized_rooms: list[str] = []
        for room_id in room_ids or []:
            room_text = str(room_id or "").strip()
            if room_text and room_text not in normalized_rooms:
                normalized_rooms.append(room_text)
        self.admin_notify_room_ids = normalized_rooms

    def get_admin_notify_rooms(self) -> list[str]:
        """获取管理员通知房间列表（优先多房间配置，回退单房间配置）。"""
        rooms: list[str] = []
        configured = getattr(self, "admin_notify_room_ids", None)
        if isinstance(configured, list):
            for room_id in configured:
                room_text = str(room_id or "").strip()
                if room_text and room_text not in rooms:
                    rooms.append(room_text)

        fallback_room = str(getattr(self, "admin_notify_room_id", "") or "").strip()
        if fallback_room and fallback_room not in rooms:
            rooms.append(fallback_room)

        return rooms

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
            msg_type="m.room.message",
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
