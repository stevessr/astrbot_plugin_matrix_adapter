import base64
import json
from pathlib import Path

from astrbot.api import logger

from ..client.http_client import MatrixAPIError
from .key_backup_crypto import CRYPTO_AVAILABLE
from .storage import build_e2ee_data_store


class CrossSigning:
    """
    交叉签名管理器

    使用 vodozemac/ed25519 进行真正的签名操作
    """

    _RECORD_CROSS_SIGNING = "cross_signing"

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        olm_machine,
        password: str | None = None,
        *,
        storage_backend: str = "json",
        namespace_key: str | None = None,
        pgsql_dsn: str = "",
        pgsql_schema: str = "public",
        pgsql_table_prefix: str = "matrix_store",
    ):
        self.client = client
        self.user_id = (
            user_id
            if isinstance(user_id, str) and user_id.startswith("@")
            else f"@{user_id}"
        )
        self.device_id = device_id
        self.olm = olm_machine
        self.password = password

        self._master_key: str | None = None
        self._self_signing_key: str | None = None
        self._user_signing_key: str | None = None

        # 私钥（Raw 32B），仅本地持久化
        self._master_priv = None
        self._self_signing_priv = None
        self._user_signing_priv = None

        # 本地持久化存储（与 E2EE store 同目录）
        try:
            store_path = Path(self.olm.store.store_path)
            self._storage_store = build_e2ee_data_store(
                folder_path=store_path,
                namespace_key=namespace_key or store_path.as_posix(),
                backend=storage_backend,
                json_filename_resolver=self._json_filename_resolver,
                pgsql_dsn=pgsql_dsn,
                pgsql_schema=pgsql_schema,
                pgsql_table_prefix=pgsql_table_prefix,
                store_name="cross_signing",
            )
        except Exception:
            self._storage_store = None

    @staticmethod
    def _json_filename_resolver(_: str) -> str:
        return "cross_signing.json"

    async def initialize(self):
        """初始化交叉签名"""
        if not CRYPTO_AVAILABLE:
            logger.debug(
                "[E2EE-CrossSign] cryptography 不可用，无法生成/签名交叉签名密钥"
            )
            return

        try:
            self._load_local_keys()

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
                    # 获取 key ID 和公钥值
                    key_id = list(keys.keys())[0]
                    server_master = list(keys.values())[0]
                    self._master_key = server_master
                    logger.debug("[E2EE-CrossSign] 发现服务器主密钥")

                    # 检测是否使用了错误的截断格式
                    # 正确格式：ed25519:<43 字符 base64 公钥>
                    # 错误格式：ed25519:<8 字符截断>
                    key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                    if len(key_part) < 20:  # 截断的 key ID 只有 8 个字符
                        logger.debug(
                            f"[E2EE-CrossSign] 检测到旧格式的 key ID (长度={len(key_part)})，需要重新生成"
                        )
                        keys_need_regen = True

            if self_keys:
                keys = self_keys.get("keys", {})
                if keys:
                    key_id = list(keys.keys())[0]
                    server_self_signing = list(keys.values())[0]
                    self._self_signing_key = server_self_signing
                    logger.debug("[E2EE-CrossSign] 发现服务器自签名密钥")

                    key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                    if len(key_part) < 20:
                        logger.debug(
                            "[E2EE-CrossSign] 检测到旧格式的 self-signing key ID，需要重新生成"
                        )
                        keys_need_regen = True

            if user_keys:
                keys = user_keys.get("keys", {})
                if keys:
                    key_id = list(keys.keys())[0]
                    server_user_signing = list(keys.values())[0]
                    self._user_signing_key = server_user_signing
                    logger.debug("[E2EE-CrossSign] 发现服务器用户签名密钥")

                    key_part = key_id.split(":", 1)[-1] if ":" in key_id else key_id
                    if len(key_part) < 20:
                        logger.debug(
                            "[E2EE-CrossSign] 检测到旧格式的 user-signing key ID，需要重新生成"
                        )
                        keys_need_regen = True

            # 如果检测到旧格式的 key ID，强制重新生成
            if keys_need_regen:
                logger.debug(
                    "[E2EE-CrossSign] 正在重新生成交叉签名密钥以修复格式问题..."
                )
                try:
                    await self._generate_and_upload_keys(force_regen=True)
                    return
                except Exception as e:
                    logger.debug(f"[E2EE-CrossSign] 重新生成交叉签名密钥失败：{e}")
                    logger.debug(
                        "[E2EE-CrossSign] 将继续使用现有密钥（交叉签名可能无法正常工作）"
                    )

            # 如果服务器已有密钥但本地缺少私钥，尝试重新生成并覆盖
            if server_master and not self._master_priv:
                logger.debug(
                    "[E2EE-CrossSign] 服务器已有交叉签名密钥，但本地缺少私钥，正在尝试重新生成..."
                )
                try:
                    await self._generate_and_upload_keys(force_regen=True)
                    return
                except Exception as e:
                    logger.debug(f"[E2EE-CrossSign] 重新生成交叉签名密钥失败：{e}")
                    logger.debug(
                        "[E2EE-CrossSign] 将继续使用服务器现有的密钥（但无法签名新设备）"
                    )
                    # 继续执行，不返回

            # 如缺少密钥则生成并上传
            if not server_master:
                try:
                    await self._generate_and_upload_keys()
                except Exception as e:
                    logger.debug(f"[E2EE-CrossSign] 生成交叉签名密钥失败：{e}")
                    logger.debug("[E2EE-CrossSign] 交叉签名功能将不可用")
            elif server_master and server_self_signing and server_user_signing:
                logger.debug("[E2EE-CrossSign] 交叉签名密钥已就绪")
                return
            elif server_master and self._master_priv:
                # 补全缺失的 self/user keys
                try:
                    await self._generate_and_upload_keys(
                        force_regen=False, reuse_master=True
                    )
                except Exception as e:
                    logger.debug(f"[E2EE-CrossSign] 补全交叉签名密钥失败：{e}")
                    logger.debug("[E2EE-CrossSign] 部分交叉签名功能可能不可用")

        except Exception as e:
            logger.debug(f"[E2EE-CrossSign] 初始化失败：{e}")

    def _b64(self, data: bytes) -> str:
        return base64.b64encode(data).decode().rstrip("=")

    def _canonical(self, obj: dict) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

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
                if k in data and data[k].get("priv"):
                    # Add padding if missing
                    priv_str = data[k]["priv"]
                    padding = 4 - len(priv_str) % 4
                    if padding != 4:
                        priv_str += "=" * padding
                    setattr(self, attr, base64.b64decode(priv_str))

                if k in data and data[k].get("pub"):
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
                    "priv": self._b64(self._master_priv),
                    "pub": self._master_key,
                },
                "self_signing": {
                    "priv": self._b64(self._self_signing_priv),
                    "pub": self._self_signing_key,
                },
                "user_signing": {
                    "priv": self._b64(self._user_signing_priv),
                    "pub": self._user_signing_key,
                },
            }
            self._storage_store.upsert(
                self._RECORD_CROSS_SIGNING,
                data,
            )
        except Exception as e:
            logger.debug(f"[E2EE-CrossSign] 保存本地交叉签名密钥失败：{e}")

    def _gen_keypair(self) -> tuple[bytes, str]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        priv = Ed25519PrivateKey.generate()
        priv_raw = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv_raw, self._b64(pub_raw)

    def _sign(self, priv_raw: bytes, payload: dict) -> str:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        payload_to_sign = dict(payload)
        payload_to_sign.pop("signatures", None)
        payload_to_sign.pop("unsigned", None)
        canonical = self._canonical(payload_to_sign)

        priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
        sig = priv.sign(canonical.encode("utf-8"))
        return self._b64(sig)

    async def _generate_and_upload_keys(
        self, force_regen: bool = False, reuse_master: bool = False
    ):
        if not CRYPTO_AVAILABLE:
            return

        if not self._master_priv or force_regen or not reuse_master:
            self._master_priv, self._master_key = self._gen_keypair()
        if not self._self_signing_priv or force_regen:
            self._self_signing_priv, self._self_signing_key = self._gen_keypair()
        if not self._user_signing_priv or force_regen:
            self._user_signing_priv, self._user_signing_key = self._gen_keypair()

        master_key = {
            "user_id": self.user_id,
            "usage": ["master"],
            "keys": {f"ed25519:{self._master_key}": self._master_key},
        }
        self_signing_key = {
            "user_id": self.user_id,
            "usage": ["self_signing"],
            "keys": {f"ed25519:{self._self_signing_key}": self._self_signing_key},
        }
        user_signing_key = {
            "user_id": self.user_id,
            "usage": ["user_signing"],
            "keys": {f"ed25519:{self._user_signing_key}": self._user_signing_key},
        }

        sig_master = self._sign(self._master_priv, master_key)
        master_key["signatures"] = {
            self.user_id: {f"ed25519:{self._master_key}": sig_master}
        }

        sig_self = self._sign(self._master_priv, self_signing_key)
        self_signing_key["signatures"] = {
            self.user_id: {f"ed25519:{self._master_key}": sig_self}
        }

        sig_user = self._sign(self._master_priv, user_signing_key)
        user_signing_key["signatures"] = {
            self.user_id: {f"ed25519:{self._master_key}": sig_user}
        }

        payload = {
            "master_key": master_key,
            "self_signing_key": self_signing_key,
            "user_signing_key": user_signing_key,
        }

        try:
            await self.client._request(
                "POST", "/_matrix/client/v3/keys/device_signing/upload", payload
            )
        except MatrixAPIError as e:
            auth_data = getattr(e, "data", {}) if isinstance(e.data, dict) else {}
            if self.password and auth_data.get("session"):
                payload["auth"] = {
                    "type": "m.login.password",
                    "user": self.user_id,
                    "password": self.password,
                    "session": auth_data.get("session"),
                }
                await self.client._request(
                    "POST", "/_matrix/client/v3/keys/device_signing/upload", payload
                )
            else:
                raise

        self._save_local_keys()
        logger.debug("[E2EE-CrossSign] 已生成并上传交叉签名密钥")

    async def upload_cross_signing_keys(self):
        if (
            not self._master_priv
            or not self._self_signing_priv
            or not self._user_signing_priv
        ):
            await self._generate_and_upload_keys(force_regen=True)
            return
        await self._generate_and_upload_keys(force_regen=False, reuse_master=True)

    async def sign_device(self, device_id: str):
        if not self._self_signing_priv or not self._self_signing_key:
            logger.debug("[E2EE-CrossSign] self-signing key 不可用，跳过设备签名")
            return
        try:
            response = await self.client.query_keys({self.user_id: [device_id]})
            device_keys = (
                response.get("device_keys", {}).get(self.user_id, {}).get(device_id)
            )
            if not device_keys:
                logger.debug("[E2EE-CrossSign] 未找到设备密钥，无法签名")
                return

            sig = self._sign(self._self_signing_priv, device_keys)
            device_keys["signatures"] = {
                self.user_id: {f"ed25519:{self._self_signing_key}": sig}
            }

            # /keys/signatures/upload 请求格式：{user_id: {device_id: device_keys}}
            await self.client._request(
                "POST",
                "/_matrix/client/v3/keys/signatures/upload",
                {self.user_id: {device_id: device_keys}},
            )
            logger.debug(f"[E2EE-CrossSign] 已签名设备：{device_id}")
        except MatrixAPIError as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名失败：{e}")
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名异常：{e}")

    async def verify_user(self, target_user_id: str):
        if not self._user_signing_priv or not self._user_signing_key:
            logger.debug("[E2EE-CrossSign] user-signing key 不可用，跳过用户验证")
            return

        response = await self.client.query_keys({target_user_id: []})
        master_key = response.get("master_keys", {}).get(target_user_id)
        if not master_key:
            logger.debug("[E2EE-CrossSign] 未找到目标用户 master key")
            return

        sig = self._sign(self._user_signing_priv, master_key)
        master_key["signatures"] = {
            self.user_id: {f"ed25519:{self._user_signing_key}": sig}
        }

        # 获取 master key 的 key ID
        keys = master_key.get("keys", {})
        if not keys:
            logger.debug("[E2EE-CrossSign] 目标用户 master key 格式无效")
            return
        key_id = list(keys.keys())[0]

        # /keys/signatures/upload 请求格式：{user_id: {key_id: master_key}}
        await self.client._request(
            "POST",
            "/_matrix/client/v3/keys/signatures/upload",
            {target_user_id: {key_id: master_key}},
        )
        logger.debug(f"[E2EE-CrossSign] 已验证用户：{target_user_id}")
