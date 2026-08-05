"""Inbound MAC key-id validation."""


class SASVerificationFlowMACKeyCheckMixin:
    """Validate that every presented MAC key is available and well-formed."""

    def _check_mac_key_ids(self, their_mac, key_ids, available_keys):
        if not key_ids:
            return False
        for key_id in key_ids:
            if key_id not in available_keys:
                return False
            if not isinstance(their_mac.get(key_id), str):
                return False
        return True


__all__ = ["SASVerificationFlowMACKeyCheckMixin"]
