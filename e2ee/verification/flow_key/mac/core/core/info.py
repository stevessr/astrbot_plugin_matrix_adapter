"""SAS MAC base info construction."""

from .......constants import INFO_PREFIX_MAC


class SASVerificationFlowMACInfoMixin:
    """Build MAC verification base info strings."""

    def _build_mac_base_info(
        self,
        sender: str,
        their_device: str,
        transaction_id: str,
    ) -> str:
        """Build the base info string used for MAC verification."""
        return f"{INFO_PREFIX_MAC}{sender}{their_device}{self.user_id}{self.device_id}{transaction_id}"

    def _build_mac_key_ids_csv(self, key_ids: list[str]) -> str:
        """Build comma-separated key IDs."""
        return ",".join(key_ids)


__all__ = ["SASVerificationFlowMACInfoMixin"]
