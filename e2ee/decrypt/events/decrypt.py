import json

from astrbot.api import logger

from ....constants import MEGOLM_ALGO, OLM_ALGO


class E2EEManagerDecryptEventMixin:
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

        if algorithm == OLM_ALGO:
            # Olm 消息解密
            sender_key = event_content.get("sender_key")
            ciphertext_data = event_content.get("ciphertext", {})
            if not isinstance(ciphertext_data, dict):
                logger.warning("Olm ciphertext is not an object")
                return None

            # Debug log
            masked_sender_key = (sender_key or "")[:8]
            logger.debug(
                f"尝试解密 Olm 消息：algorithm={algorithm} sender_key={masked_sender_key}..."
            )

            # 找到发给本设备的密文
            my_key = self._olm.curve25519_key
            if my_key not in ciphertext_data:
                target_keys = list(ciphertext_data.keys())
                masked_my_key = (my_key or "")[:16]
                masked_target_keys = [((k or "")[:16] + "...") for k in target_keys]
                logger.debug(
                    f"消息不是发给本设备的：本设备密钥={masked_my_key}... "
                    f"目标密钥={masked_target_keys}"
                )
                return None

            my_ciphertext = ciphertext_data.get(my_key)
            if not isinstance(my_ciphertext, dict):
                logger.warning(
                    f"Olm ciphertext for this device is not a dictionary: {type(my_ciphertext)}"
                )
                return None
            message_type = my_ciphertext.get("type")
            body = my_ciphertext.get("body")

            # 基本校验
            if (
                not isinstance(sender_key, str)
                or not sender_key
                or type(message_type) is not int
                or message_type not in (0, 1)
                or not isinstance(body, str)
                or not body
            ):
                logger.warning("Olm 密文缺少必要字段")
                return None

            try:
                plaintext = self._olm.decrypt_olm_message(
                    sender_key, message_type, body
                )

                logger.info(
                    f"Olm 解密成功，明文长度：{len(plaintext) if plaintext else 0}"
                )
                logger.debug(f"Olm 解密明文类型：{type(plaintext)}")

                # 解析 JSON
                if isinstance(plaintext, bytes):
                    plaintext = plaintext.decode("utf-8")

                decrypted = json.loads(plaintext)
                if not await self._validate_incoming_olm_plaintext(
                    decrypted,
                    sender,
                    sender_key,
                ):
                    logger.warning(
                        "Discarded an Olm event with invalid plaintext binding"
                    )
                    return None
                inner_type = decrypted.get("type")
                logger.info(f"Olm 解密后事件类型：{inner_type}")

                return decrypted
            except json.JSONDecodeError as je:
                logger.error(f"Olm 解密后 JSON 解析失败：{je}")
                logger.error(
                    f"明文内容（前 200 字符）：{str(plaintext)[:200] if plaintext else 'None'}"
                )
                return None
            except Exception as e:
                logger.error(f"Olm 解密失败：{e}")

                # 对于任何 Olm 解密失败，都尝试请求新会话
                # 包括：未知一次性密钥、没有可用会话等情况
                if sender:
                    await self._request_new_session(sender_key, sender)
                else:
                    logger.warning("Olm 解密失败但缺少 sender_user_id，跳过请求新会话")

                return None

        logger.warning(f"不支持的加密算法：{algorithm}")
        return None
