"""Olm ciphertext extraction and validation."""

from astrbot.api import logger


class E2EEManagerDecryptOlmCiphertextMixin:
    """Extract and validate the Olm ciphertext for this device."""

    def _extract_olm_ciphertext(
        self,
        event_content: dict,
    ) -> tuple | None:
        """Return ``(sender_key, message_type, body)`` or ``None``."""
        # Olm 消息解密
        sender_key = event_content.get("sender_key")
        ciphertext_data = event_content.get("ciphertext", {})
        if not isinstance(ciphertext_data, dict):
            logger.warning("Olm ciphertext is not an object")
            return None

        # Debug log
        masked_sender_key = (sender_key or "")[:8]
        logger.debug(
            f"尝试解密 Olm 消息：algorithm={event_content.get('algorithm')} "
            f"sender_key={masked_sender_key}..."
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

        return sender_key, message_type, body


__all__ = ["E2EEManagerDecryptOlmCiphertextMixin"]
