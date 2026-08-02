"""Verification method negotiation and identity-key selection."""

from astrbot.api import logger

from ....constants import (
    M_QR_CODE_SCAN_V1_METHOD,
    M_QR_CODE_SHOW_V1_METHOD,
    M_RECIPROCATE_V1_METHOD,
)
from ..constants import SAS_METHODS


class SASVerificationSendDeviceNegotiationMixin:
    """协商验证算法并选择需要加入 MAC 的本地身份密钥。"""

    def _get_supported_verification_methods(
        self, other_user: str | None = None
    ) -> list[str]:
        methods = list(SAS_METHODS)
        if other_user == self.user_id:
            for method in (
                M_QR_CODE_SCAN_V1_METHOD,
                M_QR_CODE_SHOW_V1_METHOD,
                M_RECIPROCATE_V1_METHOD,
            ):
                if method not in methods:
                    methods.append(method)
        return methods

    async def _peer_device_trusts_own_master_key(
        self,
        other_user: str | None = None,
        other_device: str | None = None,
        session: dict | None = None,
    ) -> bool:
        if isinstance(session, dict):
            cached = session.get("peer_device_trusts_master")
            if isinstance(cached, bool):
                return cached

        if other_user != self.user_id or not other_device:
            return True

        client = getattr(self, "client", None)
        if not client or not hasattr(client, "query_keys"):
            return False

        try:
            response = await client.query_keys({self.user_id: []})
            trust_checker = getattr(self, "_device_trusts_master_key", None)
            if callable(trust_checker):
                trusts_master = bool(
                    trust_checker(response, self.user_id, other_device)
                )
            else:
                master_key = (response.get("master_keys") or {}).get(self.user_id) or {}
                signatures = (master_key.get("signatures") or {}).get(
                    self.user_id
                ) or {}
                trusts_master = f"ed25519:{other_device}" in signatures

            if isinstance(session, dict):
                session["peer_device_trusts_master"] = trusts_master
            return trusts_master
        except Exception as e:
            logger.debug(f"[E2EE-Verify] 查询对端设备主密钥信任状态失败：{e}")
            return False

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

    @staticmethod
    def _normalize_algorithm_values(value: object) -> list[str]:
        if isinstance(value, str):
            normalized = value.strip()
            return [normalized] if normalized else []
        if isinstance(value, (list, tuple, set)):
            values: list[str] = []
            for item in value:
                if not isinstance(item, str):
                    continue
                normalized = item.strip()
                if normalized:
                    values.append(normalized)
            return values
        return []

    @staticmethod
    def _pick_algorithm(
        supported: list[str], peer_supported: list[str], fallback: str = ""
    ) -> str:
        for algorithm in supported:
            if algorithm in peer_supported:
                return algorithm
        if supported:
            return supported[0]
        if peer_supported:
            return peer_supported[0]
        return fallback


__all__ = ["SASVerificationSendDeviceNegotiationMixin"]
