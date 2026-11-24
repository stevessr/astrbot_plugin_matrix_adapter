"""Verification MAC message generation."""

from astrbot.api import logger

from .....constants import INFO_PREFIX_MAC, M_KEY_VERIFICATION_MAC
from ...crypto_utils import SAS_MAC_V2, _calculate_sas_mac


class SASVerificationSendDeviceMACMixin:
    async def _send_mac(
        self, to_user: str, to_device: str, transaction_id: str, session: dict
    ) -> bool:
        """发送 SAS MAC，严格遵循协商出的 MAC 方法。"""
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes")
        if established_sas is None and not sas_bytes:
            logger.warning("[E2EE-Verify] SAS 尚未建立，拒绝发送 MAC")
            return False

        mac_method = session.get("mac") or SAS_MAC_V2
        keys_to_mac = await self._get_verification_keys_to_mac(
            other_user=to_user, session=session
        )
        if not keys_to_mac:
            logger.warning("[E2EE-Verify] 缺少可用于发送 MAC 的本地身份密钥")
            return False

        base_info = (
            f"{INFO_PREFIX_MAC}{self.user_id}{self.device_id}"
            f"{to_user}{to_device}{transaction_id}"
        )
        key_ids = sorted(keys_to_mac.keys())

        try:
            mac_content = {
                key_id: _calculate_sas_mac(
                    method=mac_method,
                    message=keys_to_mac[key_id],
                    info=base_info + key_id,
                    established_sas=established_sas,
                    shared_secret=sas_bytes,
                )
                for key_id in key_ids
            }
            keys_mac = _calculate_sas_mac(
                method=mac_method,
                message=",".join(key_ids),
                info=base_info + "KEY_IDS",
                established_sas=established_sas,
                shared_secret=sas_bytes,
            )
        except Exception as e:
            logger.error(
                f"[E2EE-Verify] 无法使用协商的 SAS MAC 方法 {mac_method}: {e}"
            )
            raise

        content = {
            "transaction_id": transaction_id,
            "mac": mac_content,
            "keys": keys_mac,
        }
        await self._send_to_device(M_KEY_VERIFICATION_MAC, to_user, to_device, content)
        logger.info(f"[E2EE-Verify] 已发送 mac ({mac_method})")
        return True
