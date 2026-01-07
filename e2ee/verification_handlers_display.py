from astrbot.api import logger

from ..constants import (
    SAS_BYTES_LENGTH_6,
    SAS_EMOJI_COUNT_7,
)
from .verification_constants import (
    SAS_EMOJIS,
)


class SASVerificationDisplayMixin:
    async def _notify_admin_for_verification(self, session: dict, transaction_id: str):
        room_id = getattr(self, "admin_notify_room_id", None)
        if not room_id:
            return

        sender = session.get("sender", "")
        device_id = session.get("from_device") or session.get("their_device") or ""
        emojis = session.get("sas_emojis") or []
        decimals = session.get("sas_decimals") or ""
        emoji_str = " ".join(e[0] for e in emojis) if emojis else ""

        lines = [
            "SAS 验证请求（手动确认）",
            f"用户：{sender}",
            f"设备：{device_id}",
        ]
        if emoji_str:
            lines.append(f"Emoji:{emoji_str}")
        if decimals:
            lines.append(f"数字：{decimals}")
        lines.append(f"事务：{transaction_id}")
        if device_id:
            lines.append(f"使用命令：/admin verify {device_id}")

        message = "\n".join(lines)
        try:
            await self.client.send_room_message(room_id, message)
        except Exception as e:
            logger.warning(f"发送验证通知失败：{e}")

    async def _notify_user_for_approval(
        self, sender: str, device_id: str, room_id: str | None = None
    ):
        """ "Notify user for verification approval"""
        if not room_id:
            room_id = await self.client.get_user_room(sender)

        if room_id:
            message = (
                f"New device verification request from {sender} ({device_id}). "
                f"Please approve or deny."
            )
            await self.client.send_room_message(room_id, message)
        else:
            logger.warning(f"Could not find a room to notify {sender}")

    def _bytes_to_emoji(self, sas_bytes: bytes) -> list[tuple[str, str]]:
        """将 SAS 字节转换为 emoji"""
        bits = int.from_bytes(sas_bytes[:SAS_BYTES_LENGTH_6], "big")
        emojis = []
        for i in range(SAS_EMOJI_COUNT_7):
            idx = (bits >> (42 - i * 6)) & 0x3F
            emojis.append(SAS_EMOJIS[idx])
        return emojis

    def _bytes_to_decimal(self, sas_bytes: bytes) -> str:
        """将 SAS 字节转换为三组四位数字"""
        bits = int.from_bytes(sas_bytes[:5], "big")
        n1 = ((bits >> 27) & 0x1FFF) + 1000
        n2 = ((bits >> 14) & 0x1FFF) + 1000
        n3 = ((bits >> 1) & 0x1FFF) + 1000
        return f"{n1} {n2} {n3}"
