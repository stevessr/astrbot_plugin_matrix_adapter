"""
E2EE Secrets Crypto Mixin - 秘密共享相关的加密与设备密钥管理

提供 to-device 加密、设备密钥获取/校验、待处理请求管理等底层能力，
被 E2EEManagerSecretsHandlersMixin 通过 MRO 调用。

参考：https://spec.matrix.org/latest/client-server-api/#sharing-keys-between-devices
"""

from astrbot.api import logger

from ...constants import SIGNED_CURVE25519


class E2EEManagerSecretsCryptoMixin:
    """秘密共享相关的加密与设备密钥管理 Mixin"""

    @staticmethod
    def _mask_device_id(device_id: str | None) -> str:
        from ...utils.utils import mask_device_id

        return mask_device_id(device_id)

    @staticmethod
    def _mask_request_id(request_id: str | None) -> str:
        if not isinstance(request_id, str) or not request_id:
            return "<empty>"
        normalized = request_id.strip()
        if len(normalized) <= 8:
            return "***"
        return f"{normalized[:8]}..."

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
            # Only use a complete, self-signed device-keys object.  The
            # stripped convenience view in CryptoStore is insufficient for
            # authenticating one-time keys.
            device_info = await self._get_validated_device_info(
                target_user,
                target_device,
            )
            if not device_info:
                logger.warning(
                    f"[E2EE-ToDevice] Device keys not found: "
                    f"{target_user}/{target_device}"
                )
                return None

            keys = device_info.get("keys", {})
            curve25519_key = keys.get(f"curve25519:{target_device}")
            ed25519_key = keys.get(f"ed25519:{target_device}")

            if not curve25519_key:
                logger.warning(
                    f"[E2EE-ToDevice] Device has no Curve25519 key: {target_device}"
                )
                return None
            if not ed25519_key:
                logger.warning(
                    f"[E2EE-ToDevice] Device has no Ed25519 key: {target_device}"
                )
                return None

            # 检查是否已有 Olm 会话
            existing_session = self._olm.get_olm_session(curve25519_key)

            if existing_session:
                # 使用现有会话
                session = existing_session
                logger.debug(
                    "[E2EE-ToDevice] Reusing an Olm session to encrypt an event "
                    f"for {self._mask_device_id(target_device)}"
                )
            else:
                # 需要创建新会话，获取一次性密钥
                one_time_claim = {target_user: {target_device: SIGNED_CURVE25519}}
                claimed = await self.client.claim_keys(one_time_claim)
                one_time_keys = claimed.get("one_time_keys", {})

                user_otks = one_time_keys.get(target_user, {})
                device_otks = user_otks.get(target_device, {})

                if not device_otks:
                    logger.warning(
                        f"[E2EE-ToDevice] Device {target_device} has no available "
                        "one-time key"
                    )
                    return None

                selected = self._olm.select_verified_one_time_key(
                    target_user,
                    target_device,
                    ed25519_key,
                    device_otks,
                )
                if not selected:
                    logger.warning(
                        f"[E2EE-ToDevice] Device {target_device} returned no valid "
                        "signed one-time key"
                    )
                    return None
                _, one_time_key = selected

                # 创建 Olm 会话
                session = self._olm.create_outbound_session(
                    curve25519_key, one_time_key
                )
                logger.debug(
                    "[E2EE-ToDevice] Created a new Olm session for "
                    f"{self._mask_device_id(target_device)}"
                )

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
            logger.error(f"[E2EE-ToDevice] Olm encryption failed: {e}")
            return None

    async def _get_validated_device_info(
        self,
        user_id: str,
        device_id: str,
        *,
        force_query: bool = False,
    ) -> dict | None:
        """Return a complete device object after verifying its self-signature."""
        if not self._olm or not user_id or not device_id:
            return None

        if not force_query and self._store:
            get_all = getattr(self._store, "get_all_device_keys", None)
            if callable(get_all):
                all_keys = get_all()
                cached = (
                    (all_keys.get(user_id) or {}).get(device_id)
                    if isinstance(all_keys, dict)
                    else None
                )
                if self._olm.verify_device_keys(user_id, device_id, cached):
                    return cached

        try:
            response = await self.client.query_keys({user_id: [device_id]})
        except Exception as e:
            logger.warning(
                f"[E2EE-ToDevice] Device-key query failed for {user_id}/{device_id}: {e}"
            )
            return None
        device_info = (
            ((response.get("device_keys") or {}).get(user_id) or {}).get(device_id)
            if isinstance(response, dict)
            else None
        )
        if not self._olm.verify_device_keys(user_id, device_id, device_info):
            logger.warning(
                "[E2EE-ToDevice] Rejecting invalid signed device keys for "
                f"{user_id}/{device_id}"
            )
            return None
        if self._store:
            self._store.save_device_keys(user_id, device_id, device_info)
        return device_info

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

    async def _get_own_devices(self) -> list[str]:
        """获取自己的所有设备 ID"""
        try:
            response = await self.client.query_keys({self.user_id: []})
            device_keys = (response.get("device_keys") or {}).get(self.user_id) or {}
            return list(device_keys.keys())
        except Exception as e:
            logger.error(f"[E2EE-Secrets] 获取设备列表失败：{e}")
            return []

    async def _ensure_device_keys(self, user_id: str, device_ids: list[str]):
        """确保已获取指定设备的密钥"""
        try:
            # 当本地 store 不可用时，仍尝试向服务器查询（不做本地缓存）
            if not self._store:
                await self.client.query_keys({user_id: []})
                logger.debug(
                    f"[E2EE-Secrets] 本地存储不可用，已尝试从服务器查询设备密钥：{user_id}"
                )
                return

            # 检查是否已有这些设备的密钥
            missing_devices = []
            for device_id in device_ids:
                if not self._store.get_device_keys(user_id, device_id):
                    missing_devices.append(device_id)

            if missing_devices:
                # 查询缺失的设备密钥
                response = await self.client.query_keys({user_id: []})
                device_keys = (response.get("device_keys") or {}).get(user_id) or {}
                for device_id in missing_devices:
                    device_info = device_keys.get(device_id)
                    if device_info:
                        self._store.save_device_keys(user_id, device_id, device_info)
                logger.debug(
                    f"[E2EE-Secrets] 已查询设备密钥：{user_id}/{missing_devices}"
                )
        except Exception as e:
            logger.error(f"[E2EE-Secrets] 确保设备密钥失败：{e}")
