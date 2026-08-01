import base64

from astrbot.api import logger

from ...constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
)
from ..constants import (
    DEVICE_SECRET_REQUEST_FAILED,
    DEVICE_SECRET_REQUEST_NOT_NEEDED,
    DEVICE_SECRET_REQUEST_PENDING,
    DEVICE_SECRET_REQUEST_UNAVAILABLE,
)


class CrossSigningRestoreMixin:
    """本地密钥加载/保存/恢复"""

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

    async def _restore_private_keys_from_secret_storage(
        self,
        server_master: str | None,
        server_self_signing: str | None,
        server_user_signing: str | None,
    ) -> bool:
        if not self.secret_storage:
            return False

        secret_map = {
            SECRET_CROSS_SIGNING_MASTER: ("_master_priv", "_master_key", server_master),
            SECRET_CROSS_SIGNING_SELF_SIGNING: (
                "_self_signing_priv",
                "_self_signing_key",
                server_self_signing,
            ),
            SECRET_CROSS_SIGNING_USER_SIGNING: (
                "_user_signing_priv",
                "_user_signing_key",
                server_user_signing,
            ),
        }

        restored_any = False
        for secret_name, (priv_attr, pub_attr, server_pub) in secret_map.items():
            current_priv = getattr(self, priv_attr)
            if current_priv:
                derived_current = self._derive_public_key(current_priv)
                if not server_pub or derived_current == server_pub:
                    continue

            try:
                secret_bytes = await self.secret_storage.read_ssss_secret(secret_name)
            except AttributeError:
                secret_bytes = (
                    await self.secret_storage.read_secret_from_secret_storage(
                        secret_name
                    )
                )

            decoded = self._decode_secret_bytes(secret_bytes or b"")
            if not decoded:
                continue

            derived_pub = self._derive_public_key(decoded)
            expected_pub = server_pub or derived_pub
            if expected_pub and derived_pub and derived_pub != expected_pub:
                logger.warning(
                    f"[E2EE-CrossSign] 从 SSSS 恢复的 {secret_name} 与服务器公钥不匹配，忽略"
                )
                continue

            setattr(self, priv_attr, decoded)
            if expected_pub:
                setattr(self, pub_attr, expected_pub)
            restored_any = True

        if restored_any:
            self._save_local_keys()
            logger.info("[E2EE-CrossSign] 已从 Secret Storage 恢复 cross-signing 私钥")

        return restored_any

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

    async def _request_missing_private_keys_from_devices(
        self,
        server_master: str | None,
        server_self_signing: str | None,
        server_user_signing: str | None,
    ) -> str:
        if not self.request_secret_from_devices:
            return DEVICE_SECRET_REQUEST_UNAVAILABLE

        missing = self._missing_cross_signing_secret_names(
            server_master,
            server_self_signing,
            server_user_signing,
        )
        if not missing:
            return DEVICE_SECRET_REQUEST_NOT_NEEDED

        request_ids = []
        for secret_name in missing:
            if secret_name in self._pending_secret_requests:
                continue
            try:
                request_id = await self.request_secret_from_devices(secret_name)
            except Exception as e:
                logger.warning(
                    f"[E2EE-CrossSign] 向其他设备请求 secret 失败：name={secret_name} error={e}"
                )
                continue

            if request_id:
                self._pending_secret_requests.add(secret_name)
                request_ids.append(request_id)

        return (
            DEVICE_SECRET_REQUEST_PENDING
            if request_ids
            else DEVICE_SECRET_REQUEST_FAILED
        )

    async def _write_private_keys_to_secret_storage(self) -> bool | None:
        if not self.secret_storage:
            return None

        secrets_to_write = {
            SECRET_CROSS_SIGNING_MASTER: self._master_priv,
            SECRET_CROSS_SIGNING_SELF_SIGNING: self._self_signing_priv,
            SECRET_CROSS_SIGNING_USER_SIGNING: self._user_signing_priv,
        }

        wrote_any = False
        for secret_name, secret_bytes in secrets_to_write.items():
            if not secret_bytes:
                continue
            payload = base64.b64encode(secret_bytes).decode("utf-8")
            try:
                write_ok = await self.secret_storage.write_ssss_secret(
                    secret_name, payload
                )
            except AttributeError:
                write_ok = await self.secret_storage.write_secret_to_secret_storage(
                    secret_name,
                    payload,
                )
            if not write_ok:
                return False
            wrote_any = True

        return True if wrote_any else None

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
