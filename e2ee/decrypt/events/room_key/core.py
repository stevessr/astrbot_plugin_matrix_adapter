"""m.room_key event handling (Megolm session import)."""

from astrbot.api import logger

from .....constants import MEGOLM_ALGO


class E2EEManagerDecryptRoomKeyCoreMixin:
    """Import received Megolm room keys."""

    async def handle_room_key(
        self,
        event: dict,
        sender_key: str,
        *,
        sender_claimed_keys: dict[str, str] | None = None,
        sender_user_id: str | None = None,
        forwarded: bool = False,
    ):
        """
        处理 m.room_key 事件 (接收 Megolm 会话密钥)

        Args:
            event: 解密后的 m.room_key 事件内容
            sender_key: 发送者的 curve25519 密钥
            sender_claimed_keys: Olm 载荷中发送设备声明的签名密钥
            sender_user_id: Sender user ID authenticated by the Olm plaintext
            forwarded: Whether the decrypted event was m.forwarded_room_key.
        """
        if not self._olm or not self._initialized or getattr(self, "_closing", False):
            return

        if not isinstance(event, dict):
            return

        room_id = event.get("room_id")
        session_id = event.get("session_id")
        session_key = event.get("session_key")
        algorithm = event.get("algorithm")

        if algorithm != MEGOLM_ALGO:
            logger.warning(f"不支持的密钥算法：{algorithm}")
            return

        if not all(
            isinstance(value, str) and value
            for value in (room_id, session_id, session_key, sender_key)
        ):
            logger.warning("m.room_key 事件缺少必要字段")
            return

        provenance = await self._validate_room_key_provenance(
            event,
            sender_key,
            sender_user_id,
            forwarded,
        )
        if provenance is None:
            return
        forwarded_chain, original_sender_key, forwarded_ed25519, withheld = provenance

        claimed_keys = self._normalize_room_key_claims(
            sender_claimed_keys,
            forwarded_ed25519,
        )
        if claimed_keys is None:
            logger.warning("Rejected room key without an authenticated Ed25519 key")
            return

        # Only a direct m.room_key can declare shareability. A forwarded key
        # lacks this authenticated assertion and is therefore conservative.
        shared_history = not forwarded and event.get("shared_history") is True
        stored_forwarding_chain = list(forwarded_chain)
        if (
            forwarded
            and isinstance(sender_key, str)
            and sender_key
            and (
                not stored_forwarding_chain or stored_forwarding_chain[-1] != sender_key
            )
        ):
            # The content omits its current Olm sender. Persist that device as
            # the newest hop so a subsequent forward retains full provenance.
            stored_forwarding_chain.append(sender_key)

        imported = self._olm.add_megolm_inbound_session(
            room_id,
            session_id,
            session_key,
            original_sender_key,
            claimed_keys,
            stored_forwarding_chain,
            shared_history,
            None if forwarded else sender_user_id,
            withheld if forwarded else {},
        )
        if imported is False:
            logger.warning(
                f"Failed to import the Megolm key for room {room_id}; "
                "keeping the room-key request pending"
            )
            return
        logger.info(f"收到房间 {room_id} 的 Megolm 密钥")

        # Matrix requires the requester to cancel the outstanding request once
        # any device supplies the session. This also prevents repeated replies.
        await self._cancel_room_key_request(room_id, session_id)

        # 自动备份新接收到的密钥
        if self._key_backup and self.enable_key_backup:
            try:
                await self._key_backup.upload_single_key(
                    room_id=room_id,
                    session_id=session_id,
                    session_key=session_key,
                    sender_key=original_sender_key,
                    sender_claimed_keys=claimed_keys,
                    forwarding_curve25519_key_chain=stored_forwarding_chain,
                    shared_history=shared_history,
                )
            except Exception as e:
                logger.warning(f"自动备份密钥失败：{e}")
