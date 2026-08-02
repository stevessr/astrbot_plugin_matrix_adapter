"""Olm to-device encryption helpers for secret sharing."""

from astrbot.api import logger

from ....constants import SIGNED_CURVE25519


class E2EEManagerSecretsEncryptionMixin:
    """to-device Olm 加密相关能力。"""

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
