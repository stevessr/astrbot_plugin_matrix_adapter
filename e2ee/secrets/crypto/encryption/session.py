"""Reusing or creating the Olm session used for to-device encryption."""

from astrbot.api import logger

from .....constants import SIGNED_CURVE25519


class E2EEManagerSecretsEncryptionSessionMixin:
    """to-device Olm 加密相关能力。"""

    async def _get_or_create_olm_session(
        self,
        target_user: str,
        target_device: str,
        curve25519_key: str,
        ed25519_key: str,
    ) -> object | None:
        """Return an existing or freshly created outbound Olm session."""
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
            session = self._olm.create_outbound_session(curve25519_key, one_time_key)
            logger.debug(
                "[E2EE-ToDevice] Created a new Olm session for "
                f"{self._mask_device_id(target_device)}"
            )

        return session
