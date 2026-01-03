from astrbot.api import logger

from ..constants import (
    SAS_BYTES_LENGTH_6,
    SAS_EMOJI_COUNT_7,
)
from .verification_constants import (
    SAS_EMOJIS,
)


class SASVerificationDisplayMixin:
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
