"""Secret request device verification."""

from astrbot.api import logger


class E2EEManagerSecretsRequestVerifyMixin:
    """Verify the requesting device belongs to this user."""

    async def _verify_secret_request_device(
        self,
        sender: str,
        requesting_device_id: str,
    ) -> bool:
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
            return False
        return True


__all__ = ["E2EEManagerSecretsRequestVerifyMixin"]
