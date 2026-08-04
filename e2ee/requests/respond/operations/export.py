"""Megolm session export for room-key forwarding."""

from astrbot.api import logger

from ....constants import WITHHELD_UNAVAILABLE


class E2EEManagerRequestsRespondExportMixin:
    """Export a Megolm inbound session for forwarding."""

    async def _export_session(
        self,
        sender: str,
        requesting_device_id: str,
        room_id: str,
        session_id: str,
    ):
        """Export the requested Megolm session and return the export object.

        Sends a withholding notice and returns None when the session is not
        available or cannot be exported.
        """
        # 获取请求的 Megolm 会话
        session = self._olm.get_megolm_inbound_session(session_id)
        if not session:
            logger.debug(f"没有请求的会话：session={(session_id or '')[:8]}...")
            await self._send_room_key_withheld(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                WITHHELD_UNAVAILABLE,
                "The requested room key is not available on this device",
            )
            return None

        # 导出会话密钥
        try:
            first_index = self._olm.get_megolm_first_known_index(session)
            exported_key = session.export_at(first_index)
            logger.info(
                f"导出会话密钥：session={(session_id or '')[:8]}..., "
                f"first_index={first_index}"
            )
        except Exception as e:
            logger.warning(f"导出会话密钥失败：{e}")
            await self._send_room_key_withheld(
                sender,
                requesting_device_id,
                room_id,
                session_id,
                WITHHELD_UNAVAILABLE,
                "The requested room key could not be exported",
            )
            return None

        return exported_key
