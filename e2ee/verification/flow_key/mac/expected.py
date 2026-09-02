"""Expected SAS MAC computation."""

from astrbot.api import logger

from ...crypto_utils import SAS_MAC_V2, _calculate_sas_mac


class SASVerificationFlowMACExpectedMixin:
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
        method = session.get("mac") or SAS_MAC_V2
        try:
            macs = {
                key_id: _calculate_sas_mac(
                    method=method,
                    message=available_keys[key_id],
                    info=base_info + key_id,
                    established_sas=established_sas,
                    shared_secret=sas_bytes,
                )
                for key_id in key_ids
            }
            keys_mac = _calculate_sas_mac(
                method=method,
                message=key_ids_csv,
                info=base_info + "KEY_IDS",
                established_sas=established_sas,
                shared_secret=sas_bytes,
            )
        except Exception as exc:
            logger.error(f"[E2EE-Verify] SAS MAC calculation failed: {exc}")
            return None
        return macs, keys_mac
