"""In-room SAS MAC message construction."""

from astrbot.api import logger

from .....constants import INFO_PREFIX_MAC, M_KEY_VERIFICATION_MAC
from ...crypto_utils import SAS_MAC_V2, _calculate_sas_mac


class SASVerificationSendRoomMACMixin:
    """构造房间内 SAS MAC 消息。"""

    async def _send_in_room_mac(self, room_id: str, transaction_id: str, session: dict):
        """发送房间内 MAC，并严格遵循协商出的 MAC 方法。"""
        established_sas = session.get("established_sas")
        sas_bytes = session.get("sas_bytes")
        mac_method = session.get("mac") or SAS_MAC_V2

        to_user = session.get("sender")
        to_device = session.get("from_device", session.get("their_device", ""))
        keys_to_mac = await self._get_verification_keys_to_mac(
            other_user=to_user,
            session=session,
        )
        if not keys_to_mac:
            logger.warning("[E2EE-Verify] 缺少可用于发送房间内 MAC 的本地身份密钥")
            return

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

        content = {"mac": mac_content, "keys": keys_mac}
        await self._send_in_room_event(
            room_id, M_KEY_VERIFICATION_MAC, content, transaction_id
        )
        logger.info(f"[E2EE-Verify] 已发送 mac ({mac_method})")
