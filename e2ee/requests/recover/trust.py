"""Trust checks for devices belonging to the local Matrix user."""

from astrbot.api import logger

from ....constants import PREFIX_ED25519


class E2EEManagerRequestsTrustMixin:
    """通过设备存储、交叉签名或 TOFU 判定本端设备信任。"""

    async def _is_own_device_trusted(
        self,
        device_id: str,
        device_info: dict,
        key_query_response: dict | None = None,
    ) -> bool:
        """Verify an own-user device via SAS, cross-signing, or configured TOFU."""
        if (
            not self._olm
            or not isinstance(device_id, str)
            or not device_id
            or not self._olm.verify_device_keys(
                self.user_id,
                device_id,
                device_info,
            )
        ):
            return False
        ed25519_key = (device_info.get("keys") or {}).get(
            f"{PREFIX_ED25519}{device_id}"
        )
        if not isinstance(ed25519_key, str) or not ed25519_key:
            return False

        verification = getattr(self, "_verification", None)
        if verification:
            device_store = getattr(verification, "device_store", None)
            if device_store and device_store.is_trusted(
                self.user_id,
                device_id,
                ed25519_key,
            ):
                return True

        cross_signing = getattr(self, "_cross_signing", None)
        if (
            cross_signing
            and cross_signing.self_signing_key
            and cross_signing.master_key
        ):
            response = key_query_response
            if not isinstance(response, dict):
                try:
                    response = await self.client.query_keys({self.user_id: []})
                except Exception as e:
                    logger.warning(f"Unable to query cross-signing keys: {e}")
                    response = {}
            master_key = str(cross_signing.master_key)
            self_signing_key = str(cross_signing.self_signing_key)
            master_info = (response.get("master_keys") or {}).get(self.user_id)
            self_signing_info = (response.get("self_signing_keys") or {}).get(
                self.user_id
            )
            if (
                isinstance(master_info, dict)
                and (master_info.get("keys") or {}).get(f"ed25519:{master_key}")
                == master_key
                and isinstance(self_signing_info, dict)
                and (self_signing_info.get("keys") or {}).get(
                    f"ed25519:{self_signing_key}"
                )
                == self_signing_key
                and self._olm.verify_json_signature(
                    self_signing_info,
                    self.user_id,
                    f"ed25519:{master_key}",
                    master_key,
                )
                and self._olm.verify_json_signature(
                    device_info,
                    self.user_id,
                    f"ed25519:{self_signing_key}",
                    self_signing_key,
                )
            ):
                return True

        return bool(getattr(self, "trust_on_first_use", False))


__all__ = ["E2EEManagerRequestsTrustMixin"]
