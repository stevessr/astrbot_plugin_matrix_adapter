"""Trusted-device publication and post-verification refresh helpers."""

import time

from astrbot.api import logger


class CrossSigningVerificationPublicationMixin:
    """同账号设备 cross-signing 信任发布能力。"""

    async def _maybe_republish_current_device_keys_after_verification(
        self, verified_device_id: str
    ) -> None:
        current_device_id = getattr(self, "device_id", "")
        if (
            not verified_device_id
            or not current_device_id
            or verified_device_id == current_device_id
        ):
            return

        cross_signing = getattr(self, "_cross_signing", None)
        republish = getattr(cross_signing, "_republish_current_device_keys", None)
        if not callable(republish):
            return

        now = time.monotonic()
        last_ts = float(
            getattr(
                self,
                "_last_current_device_key_refresh_after_verification_ts",
                0.0,
            )
        )
        cooldown_sec = 60.0
        if now - last_ts < cooldown_sec:
            return

        self._last_current_device_key_refresh_after_verification_ts = now
        try:
            await republish()
        except Exception as e:
            logger.debug(f"验证后重发布当前设备 device_keys 失败：{e}")

    async def publish_trusted_device(self, user_id: str, device_id: str) -> bool:
        """Publish cross-signing trust for a same-account device."""
        if user_id != self.user_id:
            logger.debug("跳过发布设备信任：不是同账号设备")
            return False
        if not device_id:
            logger.debug("跳过发布设备信任：缺少 device_id")
            return False
        if not self._cross_signing:
            logger.debug("跳过发布设备信任：cross-signing 未初始化")
            return False
        if not self._cross_signing.self_signing_private_key:
            logger.debug(
                f"跳过发布设备信任：self-signing 私钥不可用 device={device_id}"
            )
            return False

        device_ok = await self._cross_signing.sign_device(device_id)
        if not device_ok:
            logger.warning(f"发布设备信任失败：{device_id}")
            return False

        master_ok = True
        sign_master = getattr(self._cross_signing, "sign_master_key_with_device", None)
        if callable(sign_master):
            master_ok = await sign_master(self.user_id)
            if not master_ok:
                logger.debug(
                    "发布 master key 设备签名未生效，但不影响同账号设备 owner-sign 状态："
                    f"{device_id}"
                )

        logger.info(f"已发布设备信任：{device_id}")
        await self._maybe_republish_current_device_keys_after_verification(device_id)
        if not master_ok:
            await self._log_same_user_verification_gap(device_id)
        return True
