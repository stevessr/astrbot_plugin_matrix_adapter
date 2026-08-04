"""Message event decryption and verification routing."""

from astrbot.api import logger

from .....client.event_types import parse_event
from .....constants import M_ROOM_ENCRYPTED, M_ROOM_MESSAGE


class MatrixEventProcessorMessagesDecryptMixin:
    """Decrypt encrypted message events and route verification events."""

    async def _handle_encrypted_message_event(
        self, room, event, sender, event_type, event_content
    ):
        """Decrypt an encrypted message event if needed.

        Returns (event, event_type, event_content) to continue processing,
        or None if the event was handled (verification) or undecryptable.
        """
        # Check if message is encrypted
        if not (event_type == M_ROOM_ENCRYPTED or event_content.get("algorithm")):
            return event, event_type, event_content

        if self.e2ee_manager:
            algorithm = event_content.get("algorithm")
            logger.debug(f"检测到加密事件，算法：{algorithm}")

            # 尝试解密
            decrypted = await self.e2ee_manager.decrypt_event(
                event_content,
                sender,
                room.room_id,
                event_id=getattr(event, "event_id", None),
            )
            if decrypted:
                decrypted_content = dict(decrypted.get("content", {}) or {})
                # Relation metadata for encrypted relation/verification
                # events is often carried in the cleartext envelope.  Keep
                # it before reparsing so edits, threads, live-message final
                # updates, and verification commitment calculations all see
                # the same m.relates_to data as plaintext events.
                cleartext_relates_to = event_content.get("m.relates_to")
                if cleartext_relates_to and "m.relates_to" not in decrypted_content:
                    decrypted_content["m.relates_to"] = cleartext_relates_to

                # 替换事件内容为解密后的内容
                event.content = decrypted_content
                event.event_type = decrypted.get("type", M_ROOM_MESSAGE)
                event.msgtype = event.content.get("msgtype", "")
                event.body = event.content.get("body", "")
                logger.debug(
                    f"成功解密消息 (room_id={room.room_id}, event_id={event.event_id}, algorithm={algorithm})"
                )

                # Check if decrypted message is a verification event (request or other steps)
                is_verification = (
                    event.event_type.startswith("m.key.verification.")
                    or event.msgtype == "m.key.verification.request"
                )

                if is_verification:
                    # Check if it's from self (same user)
                    if sender == self.user_id:
                        # Only process if from a different device
                        from_device = event.content.get("from_device")
                        if (
                            from_device
                            and self.e2ee_manager
                            and from_device == self.e2ee_manager.device_id
                        ):
                            return None  # Ignore own echo

                    logger.debug(
                        f"[EventProcessor] 检测到加密的验证事件 (type={event.event_type})"
                    )

                    # CRITICAL: For encrypted in-room verification events,
                    # m.relates_to is in the CLEARTEXT portion of the encrypted event
                    # (event_content), not in the decrypted payload.
                    # We need to copy it to the decrypted content for commitment calculation.
                    if cleartext_relates_to:
                        event.content["m.relates_to"] = cleartext_relates_to

                    # Reconstruct event_data for verification handler
                    verification_event = {
                        "type": event.event_type,
                        "sender": sender,
                        "event_id": event.event_id,
                        "content": event.content,
                    }
                    await self._handle_in_room_verification(room, verification_event)
                    return None

                event = parse_event(
                    {
                        "type": event.event_type,
                        "event_id": event.event_id,
                        "sender": sender,
                        "origin_server_ts": getattr(event, "origin_server_ts", 0),
                        "content": event.content,
                        "unsigned": getattr(event, "unsigned", None),
                    },
                    room.room_id,
                )
                event_type = event.event_type
                event_content = event.content
                return event, event_type, event_content
            else:
                logger.warning(
                    f"无法解密消息 (room_id={room.room_id}, event_id={event.event_id})"
                )
                return None
        else:
            logger.error(f"收到加密消息但 E2EE 未启用 (room_id={room.room_id})")
            return None
