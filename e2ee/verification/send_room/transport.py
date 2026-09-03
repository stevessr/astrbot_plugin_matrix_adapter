"""In-room verification event transport and algorithm helpers."""

from astrbot.api import logger

from ....constants import (
    CONTENT_KEY_RELATES_TO,
    M_ROOM_ENCRYPTED,
    REL_TYPE_REFERENCE,
)


class SASVerificationSendRoomTransportMixin:
    """为房间内验证事件添加关系并按房间状态加密发送。"""

    @staticmethod
    def _normalize_algorithm_values(value: object) -> list[str]:
        if isinstance(value, str):
            normalized = value.strip()
            return [normalized] if normalized else []
        if isinstance(value, (list, tuple, set)):
            values: list[str] = []
            for item in value:
                if not isinstance(item, str):
                    continue
                normalized = item.strip()
                if normalized:
                    values.append(normalized)
            return values
        return []

    @staticmethod
    def _pick_algorithm(
        supported: list[str], peer_supported: list[str], fallback: str = ""
    ) -> str:
        """Return only a real intersection between local and peer algorithms."""
        for algorithm in supported:
            if algorithm in peer_supported:
                return algorithm
        return fallback

    async def _send_in_room_event(
        self, room_id: str, event_type: str, content: dict, transaction_id: str
    ):
        """发送房间内验证事件"""
        try:
            # Add m.relates_to to link to the original request
            # Matrix spec: in-room verification events should use m.reference relationship
            content[CONTENT_KEY_RELATES_TO] = {
                "rel_type": REL_TYPE_REFERENCE,
                "event_id": transaction_id,
            }

            # Determine if we should encrypt based on session context
            # Check if we have an existing outbound session for this room
            should_encrypt = False
            encrypted_content = None

            if hasattr(self, "e2ee_manager") and self.e2ee_manager:
                try:
                    # Check if room has encryption enabled by looking for existing outbound session
                    if (
                        self.e2ee_manager._store
                        and self.e2ee_manager._store.get_megolm_outbound(room_id)
                    ):
                        should_encrypt = True

                    if should_encrypt:
                        encrypted_content = await self.e2ee_manager.encrypt_message(
                            room_id, event_type, content
                        )

                except Exception as e:
                    logger.warning(f"[E2EE-Verify] Failed to encrypt event: {e}")
                    # Fall back to unencrypted if encryption fails

            if encrypted_content:
                await self.client.send_room_event(
                    room_id, M_ROOM_ENCRYPTED, encrypted_content
                )
                logger.debug(f"[E2EE-Verify] 已发送加密的房间内事件：{event_type}")
            else:
                await self.client.send_room_event(room_id, event_type, content)
                logger.debug(f"[E2EE-Verify] 已发送房间内事件：{event_type}")

            touch = getattr(self, "_touch_verification_session", None)
            if callable(touch):
                touch(transaction_id)
        except Exception as e:
            logger.error(f"[E2EE-Verify] 发送房间内事件 {event_type} 失败：{e}")


__all__ = ["SASVerificationSendRoomTransportMixin"]
