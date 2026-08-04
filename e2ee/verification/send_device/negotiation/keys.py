"""Collecting local identity keys that must join verification MACs."""


class SASVerificationSendDeviceNegotiationKeysMixin:
    """协商验证算法并选择需要加入 MAC 的本地身份密钥。"""

    async def _get_verification_keys_to_mac(
        self,
        other_user: str | None = None,
        session: dict | None = None,
    ) -> dict[str, str]:
        keys_to_mac: dict[str, str] = {}

        if self.olm:
            device_key = getattr(self.olm, "ed25519_key", None)
            if isinstance(device_key, str) and device_key:
                keys_to_mac[f"ed25519:{self.device_id}"] = device_key

        cross_signing = getattr(
            getattr(self, "e2ee_manager", None), "_cross_signing", None
        )
        master_key = getattr(cross_signing, "master_key", None)
        include_master_key = False
        if other_user == self.user_id:
            include_master_key = not (
                await self._peer_device_trusts_own_master_key(
                    other_user=other_user,
                    other_device=(session or {}).get("from_device")
                    or (session or {}).get("their_device"),
                    session=session,
                )
            )
        if include_master_key and isinstance(master_key, str) and master_key:
            keys_to_mac[f"ed25519:{master_key}"] = master_key

        return keys_to_mac
