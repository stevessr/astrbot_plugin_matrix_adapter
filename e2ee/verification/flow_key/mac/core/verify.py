"""MAC digest comparison helpers."""

import hmac


class SASVerificationFlowMACVerifyMixin:
    """Compare received MACs against expected values."""

    def _verify_their_macs(
        self,
        their_mac: dict,
        key_ids: list,
        expected_mac_map: dict,
    ) -> bool:
        for key_id in key_ids:
            actual_mac = their_mac.get(key_id)
            if not hmac.compare_digest(actual_mac, expected_mac_map[key_id]):
                return False
        return True

    def _verify_keys_mac(self, their_keys: str, expected_keys_mac: str) -> bool:
        return hmac.compare_digest(their_keys, expected_keys_mac)
