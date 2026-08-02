"""Validate and process encrypted secret responses from other devices."""

import base64

from astrbot.api import logger

from ....constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
    SECRET_MEGOLM_BACKUP_V1,
)


class E2EEManagerSecretsReceiveMixin:
    """接收并处理设备间共享秘密。"""

    async def handle_secret_send(self, sender: str, content: dict, sender_key: str):
        """
        处理 m.secret.send 事件

        当收到其他设备发送的秘密时调用。

        Args:
            sender: 发送者用户 ID
            content: 事件内容（已解密）
            sender_key: Outer authenticated Olm Curve25519 sender key.
        """
        if not isinstance(content, dict):
            return

        request_id = content.get("request_id", "")
        secret = content.get("secret", "")

        logger.info(
            "[E2EE-Secrets] Received secret: "
            f"request_id={self._mask_request_id(request_id)} "
            f"secret_len={len(secret) if isinstance(secret, str) else 0}"
        )

        # 安全检查：只接受来自同一用户的秘密
        if sender != self.user_id:
            logger.warning(
                f"[E2EE-Secrets] 拒绝来自其他用户的秘密：{sender} != {self.user_id}"
            )
            return

        if not all(
            isinstance(value, str) and value
            for value in (request_id, secret, sender_key)
        ):
            logger.warning("[E2EE-Secrets] Rejecting malformed secret message")
            return

        source = await self._find_device_by_sender_key(sender_key, sender)
        if not source or source[0] != self.user_id:
            logger.warning("[E2EE-Secrets] Rejecting secret from unknown source device")
            return

        source_device = source[1]
        device_info = await self._get_validated_device_info(
            self.user_id,
            source_device,
        )
        if not device_info or not await self._is_own_device_trusted(
            source_device,
            device_info,
        ):
            logger.warning("[E2EE-Secrets] Rejecting secret from unverified device")
            return

        # 查找对应的待处理请求
        pending_request = self._get_pending_secret_request(request_id)
        if pending_request:
            secret_name = pending_request.get("name", "")
            await self._process_received_secret(secret_name, secret)
            self._remove_pending_secret_request(request_id)
        else:
            logger.debug(
                "[E2EE-Secrets] 未找到对应的待处理请求："
                f"{self._mask_request_id(request_id)}"
            )

    async def _process_received_secret(self, secret_name: str, secret_value: str):
        """
        处理接收到的秘密

        Args:
            secret_name: 秘密名称
            secret_value: Base64 编码的秘密值
        """
        try:
            secret_bytes = base64.b64decode(secret_value)

            if secret_name == SECRET_MEGOLM_BACKUP_V1:
                # 保存备份密钥
                if self._key_backup:
                    if self._key_backup.use_recovery_key_bytes(
                        secret_bytes, persist=True
                    ):
                        logger.info("[E2EE-Secrets] 已保存接收到的备份密钥")
                        # 仅在本账户缺失房间密钥时恢复
                        if self._key_backup.should_restore_for_session():
                            await self._key_backup.restore_room_keys_if_needed(
                                reason="secret_send"
                            )
                    else:
                        logger.warning("[E2EE-Secrets] 接收到的备份密钥格式无效")

            elif secret_name == SECRET_CROSS_SIGNING_MASTER:
                # 保存主交叉签名密钥
                if self._cross_signing:
                    self._cross_signing.master_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing,
                        "_pending_secret_requests",
                        None,
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的主签名密钥")

            elif secret_name == SECRET_CROSS_SIGNING_SELF_SIGNING:
                # 保存自签名密钥
                if self._cross_signing:
                    self._cross_signing.self_signing_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing,
                        "_pending_secret_requests",
                        None,
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的自签名密钥")
                    await self.publish_trusted_device(self.user_id, self.device_id)

            elif secret_name == SECRET_CROSS_SIGNING_USER_SIGNING:
                # 保存用户签名密钥
                if self._cross_signing:
                    self._cross_signing.user_signing_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing,
                        "_pending_secret_requests",
                        None,
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的用户签名密钥")

            else:
                logger.warning(f"[E2EE-Secrets] 未知的秘密类型：{secret_name}")

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 处理接收的秘密失败：{e}")
