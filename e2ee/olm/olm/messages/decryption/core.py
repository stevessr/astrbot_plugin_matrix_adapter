"""Olm message decryption and inbound-session recovery."""

import base64

from astrbot.api import logger


class OlmMachineMessageDecryptionCoreMixin:
    def decrypt_olm_message(
        self, sender_key: str, message_type: int, ciphertext: str
    ) -> str:
        """
        解密 Olm 消息

        Args:
            sender_key: 发送者的 curve25519 密钥
            message_type: 消息类型 (0=prekey, 1=normal)
            ciphertext: 密文

        Returns:
            明文
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        masked_sender_key = (sender_key or "")[:8]
        logger.debug(
            f"开始 Olm 解密：sender={masked_sender_key}... type={message_type}"
        )

        # 将 base64 密文转换为 bytes，然后创建 AnyOlmMessage
        # Matrix 使用 unpadded base64，需要添加填充
        # 添加 base64 填充
        padded_ciphertext = ciphertext + "=" * (-len(ciphertext) % 4)
        ciphertext_bytes = base64.b64decode(padded_ciphertext)

        # 尝试使用现有会话解密
        plaintext = self._decrypt_with_existing_sessions(
            sender_key,
            message_type,
            ciphertext_bytes,
        )
        if plaintext is not None:
            return plaintext

        # 如果是 prekey 消息，创建新的入站会话
        if message_type == 0:
            return self._create_inbound_session(
                sender_key,
                ciphertext,
                masked_sender_key,
            )

        # 普通消息（type=1）但没有可用的会话
        if message_type == 1:
            logger.warning(
                f"收到普通 Olm 消息但没有可用的会话：sender={masked_sender_key}... "
                "可能原因：对方认为已有会话，但本端没有。需要请求新会话。"
            )

        raise RuntimeError(f"无法解密来自 {sender_key} 的 Olm 消息")
