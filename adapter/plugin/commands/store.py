"""Device trust storage for the manual approval command."""

from astrbot.api import logger


async def _store_approved_device(
    verification, device_store, user_id: str, device_id: str, fingerprint: str
):
    """Add the device to the trust store and confirm any active SAS session."""
    device_store.add_device(user_id, device_id, fingerprint)

    approve_result = None
    approve_method = getattr(verification, "approve_device", None)
    if callable(approve_method):
        try:
            approve_result = await approve_method(device_id)
        except Exception as approve_error:
            logger.warning(f"触发验证会话确认失败：{approve_error}")
    return approve_result
