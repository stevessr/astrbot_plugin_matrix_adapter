"""Device fingerprint lookup for the manual approval command."""

from ....constants import PREFIX_ED25519


async def _fetch_device_fingerprint(client, user_id: str, device_id: str):
    """Query device keys; returns (fingerprint_or_None, error_text_or_None)."""
    response = await client.query_keys({user_id: []})

    devices = (response.get("device_keys") or {}).get(user_id) or {}
    if not devices:
        return None, f"未找到用户 {user_id} 的设备"

    device_info = devices.get(device_id, {})
    if not device_info:
        return None, f"未找到用户 {user_id} 的设备 {device_id}"

    keys = device_info.get("keys", {})
    fingerprint = keys.get(f"{PREFIX_ED25519}{device_id}")

    if not fingerprint:
        return None, f"无法获取设备 {device_id} 的 Ed25519 密钥（指纹）"
    return fingerprint, None
