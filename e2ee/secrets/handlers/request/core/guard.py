"""Secret request authorization guards."""

from astrbot.api import logger

from .....constants import SUPPORTED_SECRET_NAMES


class E2EEManagerSecretsRequestGuardMixin:
    """Validate that a secret request may be served."""

    def _check_secret_request_allowed(
        self,
        sender: str,
        requesting_device_id: str,
        request_id: str,
        name: str,
    ) -> bool:
        # 安全检查：只响应来自同一用户的请求
        if sender != self.user_id:
            logger.warning(
                f"[E2EE-Secrets] 拒绝来自其他用户的秘密请求：{sender} != {self.user_id}"
            )
            return False

        if not all(
            isinstance(value, str) and value
            for value in (requesting_device_id, request_id, name)
        ):
            logger.warning("[E2EE-Secrets] Rejecting malformed secret request")
            return False

        # 安全检查：不响应自己设备的请求
        if requesting_device_id == self.device_id:
            logger.debug("[E2EE-Secrets] 忽略来自自己设备的秘密请求")
            return False

        if name not in SUPPORTED_SECRET_NAMES:
            logger.warning(f"[E2EE-Secrets] 不支持的秘密类型：{name}")
            return False
        return True


__all__ = ["E2EEManagerSecretsRequestGuardMixin"]
