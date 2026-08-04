"""Expected MAC computation (vodozemac SAS or HKDF fallback)."""

import base64
import hashlib

from astrbot.api import logger

from ...crypto_utils import _compute_hkdf


class SASVerificationFlowMACExpectedMixin:
    """计算对端应提交的 MAC 值。"""

    async def _compute_expected_macs(
        self,
        session: dict,
        sas_bytes: bytes,
        established_sas,
        key_ids: list,
        key_ids_csv: str,
        base_info: str,
        available_keys: dict[str, str],
    ) -> tuple[dict, str] | None:
        """Return (expected_mac_map, expected_keys_mac), or None on failure."""
        try:
            if established_sas:
                expected_mac_map = {
                    key_id: established_sas.calculate_mac(
                        available_keys[key_id], (base_info + key_id)
                    )
                    for key_id in key_ids
                }
                expected_keys_mac = established_sas.calculate_mac(
                    key_ids_csv, (base_info + "KEY_IDS")
                )
            else:
                expected_mac_map = {
                    key_id: base64.b64encode(
                        _compute_hkdf(sas_bytes, b"", available_keys[key_id].encode())
                    ).decode()
                    for key_id in key_ids
                }
                expected_keys_mac = base64.b64encode(
                    hashlib.sha256(key_ids_csv.encode()).digest()
                ).decode()
        except Exception as e:
            logger.error(f"[E2EE-Verify] MAC 计算失败：{e}")
            return None
        return expected_mac_map, expected_keys_mac
