from ....constants import (
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
    PREFIX_ED25519,
)


class SASVerificationFlowIdentityMixin:
    def _get_local_device_ed25519_key(self) -> str | None:
        olm = getattr(self, "olm", None)
        device_key = getattr(olm, "ed25519_key", None)
        if isinstance(device_key, str) and device_key:
            return device_key
        if olm and hasattr(olm, "get_identity_keys"):
            try:
                keys = olm.get_identity_keys() or {}
                key_id = f"{PREFIX_ED25519}{self.device_id}"
                candidate = keys.get(key_id)
                if isinstance(candidate, str) and candidate:
                    return candidate
            except Exception:
                return None
        return None

    @staticmethod
    def _device_trusts_master_key(response: dict, user_id: str, device_id: str) -> bool:
        master_key = (response.get("master_keys") or {}).get(user_id) or {}
        signatures = (master_key.get("signatures") or {}).get(user_id) or {}
        return f"{PREFIX_ED25519}{device_id}" in signatures

    def _can_continue_with_qr(self, sender: str, methods: object) -> bool:
        if sender != self.user_id:
            return False
        can_show_to_peer = self._supports_method(methods, M_QR_CODE_SCAN_V1_METHOD)
        can_scan_peer = self._supports_method(
            methods, M_QR_CODE_SHOW_V1_METHOD
        ) and self._supports_method(methods, M_RECIPROCATE_V1_METHOD)
        return can_show_to_peer or can_scan_peer
