"""User verification operations for cross-signing."""

from astrbot.api import logger


class CrossSigningUserVerifyMixin:
    """验证其他用户的 master key。"""

    async def verify_user(self, target_user_id: str):
        if not self._user_signing_priv or not self._user_signing_key:
            logger.debug("[E2EE-CrossSign] user-signing key 不可用，跳过用户验证")
            return

        response = await self.client.query_keys({target_user_id: []})
        master_key = response.get("master_keys", {}).get(target_user_id)
        if not master_key:
            logger.debug("[E2EE-CrossSign] 未找到目标用户 master key")
            return

        signing_key_id = f"ed25519:{self._user_signing_key}"
        sig = self._sign(self._user_signing_priv, master_key)
        existing_signatures = master_key.get("signatures")
        if not isinstance(existing_signatures, dict):
            existing_signatures = {}
        user_signatures = existing_signatures.get(self.user_id)
        if not isinstance(user_signatures, dict):
            user_signatures = {}
        user_signatures[signing_key_id] = sig
        existing_signatures[self.user_id] = user_signatures
        master_key["signatures"] = existing_signatures

        # 获取 master key 的 key ID
        keys = master_key.get("keys", {})
        if not keys:
            logger.debug("[E2EE-CrossSign] 目标用户 master key 格式无效")
            return
        key_id, key_value = next(iter(keys.items()))
        master_pubkey_b64 = key_value

        # /keys/signatures/upload 请求格式：{"signatures": {user_id: {key_value: master_key}}}
        await self.client.upload_signatures(
            signatures={target_user_id: {master_pubkey_b64: master_key}}
        )
        logger.debug(f"[E2EE-CrossSign] 已验证用户：{target_user_id}")
