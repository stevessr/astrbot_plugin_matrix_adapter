"""To-device encrypted event decryption and inner-type routing."""

from astrbot.api import logger

from .....constants import (
    M_FORWARDED_ROOM_KEY,
    M_ROOM_KEY,
)


class MatrixEventProcessorToDeviceEncryptedMixin:
    """Decrypt and route encrypted to-device events."""

    async def _handle_encrypted_to_device(self, sender: str, content: dict) -> None:
        if not self.e2ee_manager:
            return
        try:
            algorithm = content.get("algorithm", "unknown")
            sender_key = content.get("sender_key")
            masked_sender_key = sender_key[:16] if isinstance(sender_key, str) else ""
            logger.debug(
                f"收到加密的 to_device 消息：algorithm={algorithm} "
                f"sender_key={masked_sender_key}..."
            )

            decrypted = await self.e2ee_manager.decrypt_event(content, sender, "")
            logger.debug(f"解密 to_device 结果：{decrypted is not None}")
            if decrypted:
                inner_type = decrypted.get("type", "")
                inner_content = decrypted.get("content", decrypted)
                logger.debug(f"解密后的事件类型：{inner_type}")
                if inner_type == M_ROOM_KEY:
                    sender_key = content.get("sender_key", "")
                    await self.e2ee_manager.handle_room_key(
                        inner_content,
                        sender_key,
                        sender_claimed_keys=decrypted.get("keys"),
                        sender_user_id=sender,
                        forwarded=False,
                    )
                    logger.debug("成功处理加密的 m.room_key 事件")
                elif inner_type == M_FORWARDED_ROOM_KEY:
                    sender_key = content.get("sender_key", "")
                    await self.e2ee_manager.handle_room_key(
                        inner_content,
                        sender_key,
                        sender_claimed_keys=decrypted.get("keys"),
                        sender_user_id=sender,
                        forwarded=True,
                    )
                    logger.debug("成功处理加密的 m.forwarded_room_key 事件")
                elif inner_type and inner_type.startswith("m.key.verification."):
                    logger.debug(f"收到加密的验证事件：{inner_type}")
                    await self.e2ee_manager.handle_verification_event(
                        inner_type, sender, inner_content
                    )
                elif inner_type == "m.secret.send":
                    logger.debug("收到加密的 m.secret.send 事件")
                    await self.e2ee_manager.handle_secret_send(
                        sender,
                        inner_content,
                        content.get("sender_key", ""),
                    )
                elif inner_type == "m.secret.request":
                    logger.debug("收到加密的 m.secret.request 事件")
                    sender_device = inner_content.get("requesting_device_id", "")
                    await self.e2ee_manager.handle_secret_request(
                        sender=sender,
                        content=inner_content,
                        sender_device=sender_device,
                    )
                elif inner_type == "m.dummy":
                    logger.debug("收到 m.dummy 事件，忽略")
                else:
                    logger.debug(
                        f"收到未知的加密 to_device 事件类型：{inner_type}，"
                        f"内容键：{list(decrypted.keys()) if isinstance(decrypted, dict) else type(decrypted)}"
                    )
            else:
                # 解密失败
                ciphertext_keys = list(content.get("ciphertext", {}).keys())
                logger.debug(
                    f"解密 to_device 消息失败，ciphertext 目标密钥：{ciphertext_keys}"
                )
        except Exception as e:
            logger.error(f"处理加密 to_device 事件失败：{e}")
