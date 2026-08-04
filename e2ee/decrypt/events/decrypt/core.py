"""Encrypted-event decryption dispatch."""

from astrbot.api import logger

from .....constants import MEGOLM_ALGO, OLM_ALGO


class E2EEManagerDecryptEventCoreMixin:
    """Guard, dispatch, and fall back for encrypted-event decryption."""

    async def decrypt_event(
        self,
        event_content: dict,
        sender: str | None,
        room_id: str,
        event_id: str | None = None,
    ) -> dict | None:
        """
        解密加密事件

        Args:
            event_content: m.room.encrypted 事件的 content
            sender: 发送者 ID
            room_id: 房间 ID

        Returns:
            解密后的事件内容，或 None
        """
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            logger.warning("E2EE 未初始化，无法解密")
            return None
        if not isinstance(event_content, dict):
            return None

        algorithm = event_content.get("algorithm")

        if algorithm == MEGOLM_ALGO:
            return await self._decrypt_megolm_event(
                event_content,
                sender=sender,
                room_id=room_id,
                event_id=event_id,
            )

        if algorithm == OLM_ALGO:
            return await self._decrypt_olm_event(
                event_content,
                sender=sender,
            )

        logger.warning(f"不支持的加密算法：{algorithm}")
        return None
