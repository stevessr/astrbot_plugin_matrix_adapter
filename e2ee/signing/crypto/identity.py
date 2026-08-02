"""Local and server device identity matching helpers."""

from astrbot.api import logger


class CrossSigningCryptoIdentityMixin:
    """读取设备身份密钥并匹配服务器状态。"""

    def _local_keys_match_server(
        self,
        server_master: str | None,
        server_self_signing: str | None,
        server_user_signing: str | None,
    ) -> bool:
        """检查本地私钥推导出的公钥是否与服务器公钥一致"""
        pairs = [
            (self._master_priv, server_master, "master"),
            (self._self_signing_priv, server_self_signing, "self_signing"),
            (self._user_signing_priv, server_user_signing, "user_signing"),
        ]
        for priv, server_pub, name in pairs:
            if priv and server_pub:
                derived = self._derive_public_key(priv)
                if derived and derived != server_pub:
                    logger.debug(f"[E2EE-CrossSign] 本地 {name} 私钥与服务器公钥不匹配")
                    return False
        return True

    def _get_local_device_identity_keys(self) -> dict[str, str]:
        if not self.olm:
            return {}
        try:
            if hasattr(self.olm, "get_identity_keys"):
                keys = self.olm.get_identity_keys()
                return keys if isinstance(keys, dict) else {}

            keys: dict[str, str] = {}
            ed25519 = getattr(self.olm, "ed25519_key", None)
            curve25519 = getattr(self.olm, "curve25519_key", None)
            if isinstance(ed25519, str) and ed25519:
                keys[f"ed25519:{self.device_id}"] = ed25519
            if isinstance(curve25519, str) and curve25519:
                keys[f"curve25519:{self.device_id}"] = curve25519
            return keys
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 读取本地设备身份密钥失败：{e}")
            return {}

    @staticmethod
    def _extract_device_identity(
        device_keys: dict | None, device_id: str
    ) -> tuple[str | None, str | None]:
        keys = (device_keys or {}).get("keys")
        if not isinstance(keys, dict):
            return None, None
        return keys.get(f"ed25519:{device_id}"), keys.get(f"curve25519:{device_id}")

    def _current_device_matches_server(
        self, device_keys: dict | None
    ) -> tuple[bool, str | None, str | None, str | None, str | None]:
        local_keys = self._get_local_device_identity_keys()
        local_ed25519 = local_keys.get(f"ed25519:{self.device_id}")
        local_curve25519 = local_keys.get(f"curve25519:{self.device_id}")
        server_ed25519, server_curve25519 = self._extract_device_identity(
            device_keys, self.device_id
        )
        matches = (
            bool(local_ed25519)
            and bool(local_curve25519)
            and local_ed25519 == server_ed25519
            and local_curve25519 == server_curve25519
        )
        return (
            matches,
            local_ed25519,
            local_curve25519,
            server_ed25519,
            server_curve25519,
        )
