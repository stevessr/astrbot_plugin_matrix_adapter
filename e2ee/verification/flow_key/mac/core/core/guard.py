"""SAS MAC guard check helpers."""


class SASVerificationFlowMACGuardMixin:
    """Guard checks for MAC verification."""

    def _mac_guard_failure(
        self,
        their_mac: dict,
        their_device: str,
        available_keys: dict,
        key_ids: list[str],
    ) -> bool:
        """Return True when a guard fails and MAC verification must abort.

        Checks device presence, available keys, and key-id validity.
        """
        if not their_device or not available_keys:
            return True
        if not self._check_mac_key_ids(their_mac, key_ids, available_keys):
            return True
        return False


__all__ = ["SASVerificationFlowMACGuardMixin"]
