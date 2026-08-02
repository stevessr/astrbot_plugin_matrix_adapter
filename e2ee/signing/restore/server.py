"""Server cross-signing state inspection helpers."""

from astrbot.api import logger

from ....constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
)


class CrossSigningRestoreServerMixin:
    """查询服务器交叉签名公钥并判断本地状态。"""

    async def _query_server_cross_signing_state(
        self,
    ) -> tuple[str | None, str | None, str | None, bool]:
        response = await self.client.query_keys({self.user_id: []})
        master_keys = response.get("master_keys", {}).get(self.user_id)
        self_keys = response.get("self_signing_keys", {}).get(self.user_id)
        user_keys = response.get("user_signing_keys", {}).get(self.user_id)

        server_master = None
        server_self_signing = None
        server_user_signing = None
        keys_need_regen = False

        if master_keys:
            keys = master_keys.get("keys", {})
            if keys:
                key_id, server_master = next(iter(keys.items()))
                self._master_key = server_master
                key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                if len(key_part) < 20:
                    keys_need_regen = True
                logger.debug("[E2EE-CrossSign] 发现服务器主密钥")

        if self_keys:
            keys = self_keys.get("keys", {})
            if keys:
                key_id, server_self_signing = next(iter(keys.items()))
                self._self_signing_key = server_self_signing
                key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                if len(key_part) < 20:
                    keys_need_regen = True
                logger.debug("[E2EE-CrossSign] 发现服务器自签名密钥")

        if user_keys:
            keys = user_keys.get("keys", {})
            if keys:
                key_id, server_user_signing = next(iter(keys.items()))
                self._user_signing_key = server_user_signing
                key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                if len(key_part) < 20:
                    keys_need_regen = True
                logger.debug("[E2EE-CrossSign] 发现服务器用户签名密钥")

        return (
            server_master,
            server_self_signing,
            server_user_signing,
            keys_need_regen,
        )

    def _has_private_keys_for_server_state(
        self,
        server_self_signing: str | None,
        server_user_signing: str | None,
    ) -> bool:
        if not self._master_priv:
            return False
        if server_self_signing and not self._self_signing_priv:
            return False
        if server_user_signing and not self._user_signing_priv:
            return False
        return True

    def _missing_cross_signing_secret_names(
        self,
        server_master: str | None,
        server_self_signing: str | None,
        server_user_signing: str | None,
    ) -> list[str]:
        missing = []
        if server_master and (
            not self._master_priv
            or self._derive_public_key(self._master_priv) != server_master
        ):
            missing.append(SECRET_CROSS_SIGNING_MASTER)
        if server_self_signing and (
            not self._self_signing_priv
            or self._derive_public_key(self._self_signing_priv) != server_self_signing
        ):
            missing.append(SECRET_CROSS_SIGNING_SELF_SIGNING)
        if server_user_signing and (
            not self._user_signing_priv
            or self._derive_public_key(self._user_signing_priv) != server_user_signing
        ):
            missing.append(SECRET_CROSS_SIGNING_USER_SIGNING)
        return missing
