"""Local cross-signing key persistence and rollback helpers."""

import base64

from astrbot.api import logger


class CrossSigningRestoreLocalMixin:
    """本地密钥加载、保存与状态回滚。"""

    def _load_local_keys(self):
        if not self._storage_store:
            return
        try:
            data = self._storage_store.get(self._RECORD_CROSS_SIGNING)
            if not isinstance(data, dict):
                return
            for k, attr in [
                ("master", "_master_priv"),
                ("self_signing", "_self_signing_priv"),
                ("user_signing", "_user_signing_priv"),
            ]:
                if data.get(k) and isinstance(data[k], dict) and data[k].get("priv"):
                    # Add padding if missing
                    priv_str = data[k]["priv"]
                    padding = 4 - len(priv_str) % 4
                    if padding != 4:
                        priv_str += "=" * padding
                    setattr(self, attr, base64.b64decode(priv_str))

                if data.get(k) and isinstance(data[k], dict) and data[k].get("pub"):
                    pub_val = data[k]["pub"]
                    if k == "master":
                        self._master_key = pub_val
                    elif k == "self_signing":
                        self._self_signing_key = pub_val
                    elif k == "user_signing":
                        self._user_signing_key = pub_val
            logger.debug("[E2EE-CrossSign] 已加载本地交叉签名密钥")
        except Exception:
            logger.debug("[E2EE-CrossSign] 读取本地交叉签名密钥失败，忽略并重新生成")

    def _save_local_keys(self):
        if not self._storage_store:
            return
        try:
            data = {
                "master": {
                    "priv": self._b64_optional(self._master_priv),
                    "pub": self._master_key,
                },
                "self_signing": {
                    "priv": self._b64_optional(self._self_signing_priv),
                    "pub": self._self_signing_key,
                },
                "user_signing": {
                    "priv": self._b64_optional(self._user_signing_priv),
                    "pub": self._user_signing_key,
                },
            }
            self._storage_store.upsert(
                self._RECORD_CROSS_SIGNING,
                data,
            )
        except Exception as e:
            logger.debug(f"[E2EE-CrossSign] 保存本地交叉签名密钥失败：{e}")

    def persist_local_keys(self):
        self._save_local_keys()

    def _restore_keys(
        self,
        master_priv,
        master_key,
        self_signing_priv,
        self_signing_key,
        user_signing_priv,
        user_signing_key,
    ):
        """上传失败时恢复旧的密钥状态"""
        self._master_priv = master_priv
        self._master_key = master_key
        self._self_signing_priv = self_signing_priv
        self._self_signing_key = self_signing_key
        self._user_signing_priv = user_signing_priv
        self._user_signing_key = user_signing_key
