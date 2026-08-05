"""Device-signing readiness checks."""

from astrbot.api import logger


class CrossSigningDeviceSignGuardMixin:
    """Check whether self-signing is available."""

    def _device_sign_ready(self) -> bool:
        if not self._self_signing_priv or not self._self_signing_key:
            logger.debug("[E2EE-CrossSign] self-signing key 不可用，跳过设备签名")
            return False
        return True


__all__ = ["CrossSigningDeviceSignGuardMixin"]
