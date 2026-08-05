"""Olm event decryption orchestration."""

import json

from astrbot.api import logger


class E2EEManagerDecryptOlmOrchestratorMixin:
    """Decrypt m.room.encrypted Olm payloads addressed to this device."""

    async def _decrypt_olm_event(
        self,
        event_content: dict,
        *,
        sender: str | None,
    ) -> dict | None:
        """Decrypt one Olm payload, validating sender binding."""
        extracted = self._extract_olm_ciphertext(event_content)
        if extracted is None:
            return None
        sender_key, message_type, body = extracted

        try:
            plaintext = self._olm.decrypt_olm_message(sender_key, message_type, body)

            logger.info(f"Olm 解密成功，明文长度：{len(plaintext) if plaintext else 0}")
            logger.debug(f"Olm 解密明文类型：{type(plaintext)}")

            decrypted = await self._parse_decrypted_olm_payload(
                plaintext,
                sender=sender,
                sender_key=sender_key,
            )
            if decrypted is None:
                logger.warning("Discarded an Olm event with invalid plaintext binding")
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


__all__ = ["E2EEManagerDecryptOlmOrchestratorMixin"]
