from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent
from ..constants import PREFIX_ED25519
from astrbot.core.star.register import register_command


@register_command("approve_device", help="Approve a Matrix device manually")
async def approve_device(event: AstrMessageEvent, user_id: str, device_id: str):
    """
    Approve a Matrix device manually.

    Args:
        user_id: The Matrix user ID (e.g., @user:example.com)
        device_id: The device ID to approve
    """
    # Check if this is a Matrix event
    if event.platform_meta.name != "matrix":
        await event.send("This command is only available on Matrix.")
        return

    # Access E2EE Manager
    # Note: e2ee_manager is injected into the event by MatrixPlatformAdapter
    e2ee_manager = getattr(event, "e2ee_manager", None)

    if not e2ee_manager:
        await event.send("End-to-End Encryption is not enabled or not available.")
        return

    if not e2ee_manager._verification:
        await event.send("Verification module is not initialized.")
        return

    try:
        # Query device keys to get the fingerprint
        # This mirrors the logic in SASVerification._handle_in_room_request
        client = event.client
        response = await client.query_keys({user_id: []})

        devices = response.get("device_keys", {}).get(user_id, {})
        if not devices:
            await event.send(f"No devices found for user {user_id}")
            return

        device_info = devices.get(device_id, {})
        if not device_info:
            await event.send(f"Device {device_id} not found for user {user_id}")
            return

        keys = device_info.get("keys", {})
        fingerprint = keys.get(f"{PREFIX_ED25519}{device_id}")

        if not fingerprint:
            await event.send(f"Could not find Ed25519 key (fingerprint) for device {device_id}")
            return

        # Add to trusted devices
        e2ee_manager._verification.device_store.add_device(user_id, device_id, fingerprint)

        await event.send(f"✅ Device approved:\nUser: {user_id}\nDevice: {device_id}\nFingerprint: {fingerprint}")
        logger.info(f"Manually approved device {user_id}|{device_id} via command")

    except Exception as e:
        logger.error(f"Failed to approve device: {e}")
        await event.send(f"❌ Failed to approve device: {e}")
