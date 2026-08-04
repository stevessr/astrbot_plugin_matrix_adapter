"""Peer-device master-key trust lookups for verification MACs."""

from astrbot.api import logger


class SASVerificationSendDeviceNegotiationTrustMixin:
    """协商验证算法并选择需要加入 MAC 的本地身份密钥。"""

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
