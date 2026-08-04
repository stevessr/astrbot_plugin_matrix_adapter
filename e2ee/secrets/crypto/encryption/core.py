"""Olm to-device encryption helpers for secret sharing."""

from astrbot.api import logger


class E2EEManagerSecretsEncryptionCoreMixin:
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

            session = await self._get_or_create_olm_session(
                target_user,
                target_device,
                curve25519_key,
                ed25519_key,
            )
            if not session:
                return None

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
