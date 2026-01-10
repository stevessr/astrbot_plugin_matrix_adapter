"""
E2EE Manager Secrets Mixin - 处理设备间秘密共享

实现 Matrix m.secret.request 和 m.secret.send 事件的处理。
用于支持"从其他设备传输"聊天记录备份密钥等功能。

参考：https://spec.matrix.org/latest/client-server-api/#sharing-keys-between-devices
"""

import base64

from astrbot.api import logger

from ..constants import (
    M_SECRET_REQUEST,
    M_SECRET_SEND,
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
    SECRET_MEGOLM_BACKUP_V1,
)


class E2EEManagerSecretsMixin:
    """处理设备间秘密共享的 Mixin"""

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
        action = content.get("action")
        requesting_device_id = content.get("requesting_device_id", sender_device)
        request_id = content.get("request_id", "")
        name = content.get("name", "")

        logger.info(
            f"[E2EE-Secrets] 收到秘密请求：action={action} name={name} "
            f"device={requesting_device_id} request_id={request_id[:8]}..."
        )

        # 只处理 request 动作（忽略 request_cancellation）
        if action != "request":
            if action == "request_cancellation":
                logger.debug(f"[E2EE-Secrets] 秘密请求已取消：request_id={request_id}")
            return

        # 安全检查：只响应来自同一用户的请求
        if sender != self.user_id:
            logger.warning(
                f"[E2EE-Secrets] 拒绝来自其他用户的秘密请求：{sender} != {self.user_id}"
            )
            return

        # 安全检查：不响应自己设备的请求
        if requesting_device_id == self.device_id:
            logger.debug("[E2EE-Secrets] 忽略来自自己设备的秘密请求")
            return

        # 检查请求的秘密类型是否支持
        supported_secrets = {
            SECRET_MEGOLM_BACKUP_V1,
            SECRET_CROSS_SIGNING_MASTER,
            SECRET_CROSS_SIGNING_SELF_SIGNING,
            SECRET_CROSS_SIGNING_USER_SIGNING,
        }

        if name not in supported_secrets:
            logger.warning(f"[E2EE-Secrets] 不支持的秘密类型：{name}")
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
                if self._key_backup and self._key_backup._backup_key:
                    key_bytes = self._key_backup._backup_key
                    return base64.b64encode(key_bytes).decode("utf-8")
                else:
                    logger.debug("[E2EE-Secrets] 备份密钥不可用")
                    return None

            elif secret_name == SECRET_CROSS_SIGNING_MASTER:
                # 获取主交叉签名密钥
                if self._cross_signing and hasattr(
                    self._cross_signing, "_master_private_key"
                ):
                    key = self._cross_signing._master_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 主签名密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_SELF_SIGNING:
                # 获取自签名密钥
                if self._cross_signing and hasattr(
                    self._cross_signing, "_self_signing_private_key"
                ):
                    key = self._cross_signing._self_signing_private_key
                    if key:
                        return base64.b64encode(key).decode("utf-8")
                logger.debug("[E2EE-Secrets] 自签名密钥不可用")
                return None

            elif secret_name == SECRET_CROSS_SIGNING_USER_SIGNING:
                # 获取用户签名密钥
                if self._cross_signing and hasattr(
                    self._cross_signing, "_user_signing_private_key"
                ):
                    key = self._cross_signing._user_signing_private_key
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
                    event_type="m.room.encrypted",
                    messages={target_user: {target_device: encrypted_content}},
                )
                logger.info(
                    f"[E2EE-Secrets] 已发送秘密 {secret_name} 到设备 {target_device}"
                )
            else:
                logger.error(f"[E2EE-Secrets] 无法加密秘密消息到设备 {target_device}")

        except Exception as e:
            logger.error(f"[E2EE-Secrets] 发送秘密失败：{e}")

    async def _encrypt_to_device(
        self, target_user: str, target_device: str, event_type: str, content: dict
    ) -> dict | None:
        """
        使用 Olm 加密 to-device 消息

        Args:
            target_user: 目标用户 ID
            target_device: 目标设备 ID
            event_type: 内部事件类型
            content: 要加密的内容

        Returns:
            加密后的内容，或 None
        """
        if not self._olm:
            return None

        try:
            # 获取目标设备的密钥
            device_keys = self._store.get_device_keys(target_user, target_device)
            if not device_keys:
                logger.warning(
                    f"[E2EE-Secrets] 未找到设备密钥：{target_user}/{target_device}"
                )
                return None

            curve25519_key = device_keys.get("curve25519")
            ed25519_key = device_keys.get("ed25519", "")
            if not curve25519_key:
                logger.warning(
                    f"[E2EE-Secrets] 设备没有 Curve25519 密钥：{target_device}"
                )
                return None

            # 检查是否已有 Olm 会话
            existing_session = self._olm.get_olm_session(curve25519_key)

            if existing_session:
                # 使用现有会话
                session = existing_session
                logger.debug(
                    f"[E2EE-Secrets] 复用现有 Olm 会话向 {target_device} 发送秘密"
                )
            else:
                # 需要创建新会话，获取一次性密钥
                from ..constants import SIGNED_CURVE25519

                one_time_claim = {target_user: {target_device: SIGNED_CURVE25519}}
                claimed = await self.client.claim_keys(one_time_claim)
                one_time_keys = claimed.get("one_time_keys", {})

                user_otks = one_time_keys.get(target_user, {})
                device_otks = user_otks.get(target_device, {})

                if not device_otks:
                    logger.warning(
                        f"[E2EE-Secrets] 设备 {target_device} 没有可用的一次性密钥"
                    )
                    return None

                # 取第一个一次性密钥
                otk_id = list(device_otks.keys())[0]
                otk_data = device_otks[otk_id]
                one_time_key = (
                    otk_data.get("key") if isinstance(otk_data, dict) else otk_data
                )

                # 创建 Olm 会话
                session = self._olm.create_outbound_session(
                    curve25519_key, one_time_key
                )
                logger.debug(f"[E2EE-Secrets] 为 {target_device} 创建新 Olm 会话")

            # 使用 Olm 加密
            encrypted = self._olm.encrypt_olm(
                their_identity_key=curve25519_key,
                content=content,
                session=session,
                recipient_user_id=target_user,
                recipient_ed25519_key=ed25519_key,
                event_type=event_type,
            )

            return encrypted

        except Exception as e:
            logger.error(f"[E2EE-Secrets] Olm 加密失败：{e}")
            return None

    async def handle_secret_send(self, sender: str, content: dict):
        """
        处理 m.secret.send 事件

        当收到其他设备发送的秘密时调用。

        Args:
            sender: 发送者用户 ID
            content: 事件内容（已解密）
        """
        request_id = content.get("request_id", "")
        secret = content.get("secret", "")

        logger.info(
            f"[E2EE-Secrets] 收到秘密：request_id={request_id[:8]}... "
            f"secret_len={len(secret)}"
        )

        # 安全检查：只接受来自同一用户的秘密
        if sender != self.user_id:
            logger.warning(
                f"[E2EE-Secrets] 拒绝来自其他用户的秘密：{sender} != {self.user_id}"
            )
            return

        if not secret:
            logger.warning("[E2EE-Secrets] 收到的秘密为空")
            return

        # 查找对应的待处理请求
        pending_request = self._get_pending_secret_request(request_id)
        if pending_request:
            secret_name = pending_request.get("name", "")
            await self._process_received_secret(secret_name, secret)
            self._remove_pending_secret_request(request_id)
        else:
            logger.debug(f"[E2EE-Secrets] 未找到对应的待处理请求：{request_id}")

    def _get_pending_secret_request(self, request_id: str) -> dict | None:
        """获取待处理的秘密请求"""
        if not hasattr(self, "_pending_secret_requests"):
            self._pending_secret_requests = {}
        return self._pending_secret_requests.get(request_id)

    def _remove_pending_secret_request(self, request_id: str):
        """移除待处理的秘密请求"""
        if hasattr(self, "_pending_secret_requests"):
            self._pending_secret_requests.pop(request_id, None)

    def _add_pending_secret_request(self, request_id: str, secret_name: str):
        """添加待处理的秘密请求"""
        if not hasattr(self, "_pending_secret_requests"):
            self._pending_secret_requests = {}
        self._pending_secret_requests[request_id] = {"name": secret_name}

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
                    self._key_backup._backup_key = secret_bytes
                    self._key_backup._save_backup_key()
                    logger.info("[E2EE-Secrets] 已保存接收到的备份密钥")

                    # 尝试从备份恢复密钥
                    await self._key_backup.restore_room_keys()

            elif secret_name == SECRET_CROSS_SIGNING_MASTER:
                if self._cross_signing:
                    self._cross_signing._master_private_key = secret_bytes
                    logger.info("[E2EE-Secrets] 已保存接收到的主签名密钥")

            elif secret_name == SECRET_CROSS_SIGNING_SELF_SIGNING:
                if self._cross_signing:
                    self._cross_signing._self_signing_private_key = secret_bytes
                    logger.info("[E2EE-Secrets] 已保存接收到的自签名密钥")

            elif secret_name == SECRET_CROSS_SIGNING_USER_SIGNING:
                if self._cross_signing:
                    self._cross_signing._user_signing_private_key = secret_bytes
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
        import uuid

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

    async def _get_own_devices(self) -> list[str]:
        """获取自己的所有设备 ID"""
        try:
            response = await self.client.query_keys([self.user_id])
            device_keys = response.get("device_keys", {}).get(self.user_id, {})
            return list(device_keys.keys())
        except Exception as e:
            logger.error(f"[E2EE-Secrets] 获取设备列表失败：{e}")
            return []

    async def _ensure_device_keys(self, user_id: str, device_ids: list[str]):
        """确保已获取指定设备的密钥"""
        try:
            # 检查是否已有这些设备的密钥
            missing_devices = []
            for device_id in device_ids:
                if not self._store.get_device_keys(user_id, device_id):
                    missing_devices.append(device_id)

            if missing_devices:
                # 查询缺失的设备密钥
                await self.client.query_keys([user_id])
                logger.debug(
                    f"[E2EE-Secrets] 已查询设备密钥：{user_id}/{missing_devices}"
                )
        except Exception as e:
            logger.error(f"[E2EE-Secrets] 确保设备密钥失败：{e}")
