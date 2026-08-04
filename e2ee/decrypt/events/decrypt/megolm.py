"""Megolm room-event decryption with backup-restore fallback."""

from astrbot.api import logger


class E2EEManagerDecryptMegolmMixin:
    """Decrypt m.room.encrypted Megolm events and recover missing keys."""

    async def _decrypt_megolm_event(
        self,
        event_content: dict,
        *,
        sender: str | None,
        room_id: str,
        event_id: str | None,
    ) -> dict | None:
        """Decrypt one Megolm payload, retrying from server backup."""
        session_id = event_content.get("session_id")
        ciphertext = event_content.get("ciphertext")
        sender_key = event_content.get("sender_key")
        masked_session_id = (session_id or "")[:8]

        if (
            not isinstance(session_id, str)
            or not session_id
            or not isinstance(ciphertext, str)
            or not ciphertext
        ):
            logger.warning("缺少 session_id 或 ciphertext")
            return None

        decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
        if decrypted and await self._validate_incoming_megolm_plaintext(
            decrypted,
            sender=sender,
            room_id=room_id,
            session_id=session_id,
            ciphertext=ciphertext,
            event_id=event_id,
        ):
            logger.debug(f"成功解密 Megolm 消息 (session: {masked_session_id}...)")
            return decrypted
        if decrypted:
            logger.warning(
                "Discarded Megolm plaintext with invalid room/sender binding"
            )
            return None

        # 解密失败，尝试请求密钥
        logger.info(f"尝试请求房间密钥：session={masked_session_id}...")

        # 1. 仅在本账户缺失密钥时尝试从服务器备份恢复
        if self._key_backup and self._key_backup.should_restore_for_session(
            session_id=session_id
        ):
            await self._key_backup.restore_room_keys_if_needed(
                session_id=session_id,
                reason="decrypt_failed",
            )
            # 再次尝试解密
            decrypted = self._olm.decrypt_megolm(session_id, ciphertext)
            if decrypted and await self._validate_incoming_megolm_plaintext(
                decrypted,
                sender=sender,
                room_id=room_id,
                session_id=session_id,
                ciphertext=ciphertext,
                event_id=event_id,
            ):
                logger.info(f"从备份恢复后成功解密：{masked_session_id}...")
                return decrypted
            if decrypted:
                return None

        # 2. 发送 m.room_key_request
        await self._request_room_key(room_id, session_id, sender_key, sender=sender)

        return None
