"""
E2EE Secrets Handlers Mixin - 处理设备间秘密共享的请求/响应流程

实现 Matrix m.secret.request 和 m.secret.send 事件的处理。
用于支持"从其他设备传输"聊天记录备份密钥等功能。

参考：https://spec.matrix.org/latest/client-server-api/#sharing-keys-between-devices
"""

import base64
import uuid

from astrbot.api import logger

from ...constants import (
    M_ROOM_ENCRYPTED,
    M_SECRET_REQUEST,
    M_SECRET_SEND,
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
    SECRET_MEGOLM_BACKUP_V1,
)
from ..constants import SUPPORTED_SECRET_NAMES


class E2EEManagerSecretsHandlersMixin:
    """处理设备间秘密共享请求/响应流程的 Mixin"""

    async def handle_secret_request(
        self, sender: str, content: dict, sender_device: str
    ):
        """
        处理 m.secret.request 事件

        当其他设备（通常是同一用户的新设备）请求秘密时调用。
        只响应来自同一用户的已验证设备的请求。

        Args:
            sender: 发送者用户 ID
            content: 事件内容
            sender_device: 发送设备 ID
        """
        if not isinstance(content, dict):
            return
        action = content.get("action")
        # Prefer the authenticated sender_device from to-device metadata over
        # the unauthenticated requesting_device_id inside the event content
        # (defense-in-depth; the device is still verified later).
        requesting_device_id = sender_device or content.get(
            "requesting_device_id", sender_device
        )
        request_id = content.get("request_id", "")
        name = content.get("name", "")

        logger.info(
            f"[E2EE-Secrets] 收到秘密请求：action={action} name={name} "
            f"device={self._mask_device_id(requesting_device_id)} "
            f"request_id={self._mask_request_id(request_id)}"
        )

        # 只处理 request 动作（忽略 request_cancellation）
        if action != "request":
            if action == "request_cancellation":
                logger.debug(
                    "[E2EE-Secrets] 秘密请求已取消："
                    f"request_id={self._mask_request_id(request_id)}"
                )
            return

        # 安全检查：只响应来自同一用户的请求
        if sender != self.user_id:
            logger.warning(
                f"[E2EE-Secrets] 拒绝来自其他用户的秘密请求：{sender} != {self.user_id}"
            )
            return

        if not all(
            isinstance(value, str) and value
            for value in (requesting_device_id, request_id, name)
        ):
            logger.warning("[E2EE-Secrets] Rejecting malformed secret request")
            return

        # 安全检查：不响应自己设备的请求
        if requesting_device_id == self.device_id:
            logger.debug("[E2EE-Secrets] 忽略来自自己设备的秘密请求")
            return

        if name not in SUPPORTED_SECRET_NAMES:
            logger.warning(f"[E2EE-Secrets] 不支持的秘密类型：{name}")
            return

        device_info = await self._get_validated_device_info(
            sender,
            requesting_device_id,
            force_query=True,
        )
        if not device_info or not await self._is_own_device_trusted(
            requesting_device_id,
            device_info,
        ):
            logger.warning(
                "[E2EE-Secrets] Rejecting secret request from unverified device: "
                f"{self._mask_device_id(requesting_device_id)}"
            )
            return

        # 获取请求的秘密
        secret_value = await self._get_secret_for_sharing(name)
        if not secret_value:
            logger.warning(f"[E2EE-Secrets] 无法获取秘密：{name}")
            return

        # 发送秘密给请求的设备
        await self._send_secret(
            target_user=sender,
            target_device=requesting_device_id,
            request_id=request_id,
            secret_name=name,
            secret_value=secret_value,
        )

    async def _get_secret_for_sharing(self, secret_name: str) -> str | None:
        """
        获取要共享的秘密值

        Args:
            secret_name: 秘密名称

        Returns:
            Base64 编码的秘密值，或 None
        """
        try:
            if secret_name == SECRET_MEGOLM_BACKUP_V1:
                # 获取备份密钥
                if self._key_backup:
                    key_bytes = self._key_backup.recovery_key_bytes
                    if not key_bytes:
                        key_bytes = self._key_backup.load_extracted_key()
                    if not key_bytes:
                        logger.debug("[E2EE-Secrets] 备份密钥不可用")
                        return None
                    return base64.b64encode(key_bytes).decode("utf-8")
                logger.debug("[E2EE-Secrets] 备份密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_MASTER:
                # 获取主交叉签名密钥
                if (
                    self._cross_signing
                    and self._cross_signing.master_private_key is not None
                ):
                    key = self._cross_signing.master_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 主签名密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_SELF_SIGNING:
                # 获取自签名密钥
                if (
                    self._cross_signing
                    and self._cross_signing.self_signing_private_key is not None
                ):
                    key = self._cross_signing.self_signing_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 自签名密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_USER_SIGNING:
                # 获取用户签名密钥
                if (
                    self._cross_signing
                    and self._cross_signing.user_signing_private_key is not None
                ):
                    key = self._cross_signing.user_signing_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 用户签名密钥不可用")
                return None

            else:
                logger.warning(f"[E2EE-Secrets] 未知的秘密类型：{secret_name}")
                return None

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 获取秘密失败：{e}")
            return None

    async def _send_secret(
        self,
        target_user: str,
        target_device: str,
        request_id: str,
        secret_name: str,
        secret_value: str,
    ):
        """
        发送秘密给请求的设备

        Args:
            target_user: 目标用户 ID
            target_device: 目标设备 ID
            request_id: 原始请求 ID
            secret_name: 秘密名称
            secret_value: Base64 编码的秘密值
        """
        try:
            # 构造 m.secret.send 内容
            content = {
                "request_id": request_id,
                "secret": secret_value,
            }

            # 需要加密发送
            # 首先获取目标设备的密钥
            await self._ensure_device_keys(target_user, [target_device])

            # 加密内容
            encrypted_content = await self._encrypt_to_device(
                target_user=target_user,
                target_device=target_device,
                event_type=M_SECRET_SEND,
                content=content,
            )

            if encrypted_content:
                # 发送加密的 to-device 消息
                await self.client.send_to_device(
                    event_type=M_ROOM_ENCRYPTED,
                    messages={target_user: {target_device: encrypted_content}},
                )
                mark_succeeded = getattr(self, "_mark_olm_send_succeeded", None)
                if callable(mark_succeeded):
                    mark_succeeded(target_user, target_device)
                logger.info(
                    "[E2EE-Secrets] 已发送秘密 "
                    f"{secret_name} 到设备 {self._mask_device_id(target_device)}"
                )
            else:
                logger.error(
                    "[E2EE-Secrets] 无法加密秘密消息到设备 "
                    f"{self._mask_device_id(target_device)}"
                )

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 发送秘密失败：{e}")

    async def handle_secret_send(
        self,
        sender: str,
        content: dict,
        sender_key: str,
    ):
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
                if self._cross_signing:
                    self._cross_signing.master_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing, "_pending_secret_requests", None
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的主签名密钥")

            elif secret_name == SECRET_CROSS_SIGNING_SELF_SIGNING:
                if self._cross_signing:
                    self._cross_signing.self_signing_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing, "_pending_secret_requests", None
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的自签名密钥")
                    await self.publish_trusted_device(self.user_id, self.device_id)

            elif secret_name == SECRET_CROSS_SIGNING_USER_SIGNING:
                if self._cross_signing:
                    self._cross_signing.user_signing_private_key = secret_bytes
                    pending = getattr(
                        self._cross_signing, "_pending_secret_requests", None
                    )
                    if isinstance(pending, set):
                        pending.discard(secret_name)
                    self._cross_signing.persist_local_keys()
                    logger.info("[E2EE-Secrets] 已保存接收到的用户签名密钥")

            else:
                logger.warning(f"[E2EE-Secrets] 未知的秘密类型：{secret_name}")

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 处理接收的秘密失败：{e}")

    async def request_secret_from_devices(self, secret_name: str) -> str | None:
        """
        向其他设备请求秘密

        Args:
            secret_name: 秘密名称

        Returns:
            请求 ID
        """
        request_id = str(uuid.uuid4())

        try:
            # 获取自己的其他设备
            own_devices = await self._get_own_devices()
            if not own_devices:
                logger.warning("[E2EE-Secrets] 没有其他设备可请求秘密")
                return None

            # 构造请求内容
            content = {
                "action": "request",
                "requesting_device_id": self.device_id,
                "request_id": request_id,
                "name": secret_name,
            }

            # 记录待处理请求
            self._add_pending_secret_request(request_id, secret_name)

            # 向所有其他设备发送请求
            messages = {}
            for device_id in own_devices:
                if device_id != self.device_id:
                    messages[device_id] = content

            if messages:
                await self.client.send_to_device(
                    event_type=M_SECRET_REQUEST,
                    messages={self.user_id: messages},
                )
                logger.info(
                    f"[E2EE-Secrets] 已向 {len(messages)} 个设备请求秘密 {secret_name}"
                )
                return request_id
            else:
                logger.warning("[E2EE-Secrets] 没有其他设备可请求")
                return None

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 请求秘密失败：{e}")
            return None
