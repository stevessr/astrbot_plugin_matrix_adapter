"""Collection of keys used for MAC verification."""

from astrbot.api import logger

from .....constants import PREFIX_ED25519


class SASVerificationFlowMACKeysMixin:
    """收集并缓存用于 MAC 校验的设备与主签名密钥。"""

    async def _collect_mac_verification_keys(
        self,
        session: dict,
        sender: str,
        their_device: str,
    ) -> dict[str, str]:
        available_keys: dict[str, str] = {}
        fingerprint = session.get("fingerprint")
        if fingerprint and their_device:
            available_keys[f"{PREFIX_ED25519}{their_device}"] = fingerprint

        master_key = session.get("master_key")
        master_key_id = session.get("master_key_id")
        if master_key_id and master_key:
            available_keys[master_key_id] = master_key

        if their_device and (
            f"{PREFIX_ED25519}{their_device}" not in available_keys or not master_key_id
        ):
            try:
                resp = await self.client.query_keys({sender: []})
                devices = resp.get("device_keys") or {}
                user_devices = devices.get(sender) or {}
                device_info = user_devices.get(their_device) or {}
                keys = device_info.get("keys") or {}
                fingerprint = keys.get(f"{PREFIX_ED25519}{their_device}")
                if fingerprint:
                    session["fingerprint"] = fingerprint
                    available_keys[f"{PREFIX_ED25519}{their_device}"] = fingerprint

                master_key_obj = (resp.get("master_keys") or {}).get(sender) or {}
                master_keys = master_key_obj.get("keys") or {}
                if master_keys:
                    fetched_master_key_id, fetched_master_key = next(
                        iter(master_keys.items())
                    )
                    session["master_key_id"] = fetched_master_key_id
                    session["master_key"] = fetched_master_key
                    available_keys[fetched_master_key_id] = fetched_master_key
            except Exception as e:
                logger.warning(f"[E2EE-Verify] 查询 MAC 校验密钥失败：{e}")

        return available_keys
