import asyncio
import base64
import json
from pathlib import Path

from astrbot.api import logger

from ..client.http_client import MatrixAPIError
from ..plugin_config import get_plugin_config
from .key_backup_crypto import CRYPTO_AVAILABLE
from .storage import build_e2ee_data_store


class CrossSigning:
    """
    交叉签名管理器

    使用 vodozemac/ed25519 进行真正的签名操作
    """

    @property
    def has_master_key(self) -> bool:
        return bool(self._master_key)

    @property
    def master_key(self) -> str | None:
        return self._master_key

    @property
    def self_signing_key(self) -> str | None:
        return self._self_signing_key

    @property
    def device_key_id(self) -> str:
        return f"ed25519:{self.device_id}"

    @property
    def master_private_key(self) -> bytes | None:
        return self._master_priv

    @master_private_key.setter
    def master_private_key(self, value: bytes | None) -> None:
        self._master_priv = value

    @property
    def self_signing_private_key(self) -> bytes | None:
        return self._self_signing_priv

    @self_signing_private_key.setter
    def self_signing_private_key(self, value: bytes | None) -> None:
        self._self_signing_priv = value

    @property
    def user_signing_private_key(self) -> bytes | None:
        return self._user_signing_priv

    @user_signing_private_key.setter
    def user_signing_private_key(self, value: bytes | None) -> None:
        self._user_signing_priv = value

    _RECORD_CROSS_SIGNING = "cross_signing"

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        olm_machine,
        password: str | None = None,
        *,
        namespace_key: str | None = None,
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

        self.storage_backend_config = get_plugin_config().storage_backend_config

        # 本地持久化存储（与 E2EE store 同目录）
        try:
            store_path = Path(self.olm.store.store_path)
            self._storage_store = build_e2ee_data_store(
                folder_path=store_path,
                namespace_key=namespace_key or store_path.as_posix(),
                storage_backend_config=self.storage_backend_config,
                json_filename_resolver=self._json_filename_resolver,
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
                    key_id, server_master = next(iter(keys.items()))
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
                    key_id, server_self_signing = next(iter(keys.items()))
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
                    key_id, server_user_signing = next(iter(keys.items()))
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

            # 验证本地私钥与服务器公钥是否匹配
            if (
                server_master
                and self._master_priv
                and not self._local_keys_match_server(
                    server_master, server_self_signing, server_user_signing
                )
            ):
                logger.debug(
                    "[E2EE-CrossSign] 本地私钥与服务器公钥不匹配"
                    "（可能在其他客户端重置），正在重新生成..."
                )
                try:
                    await self._generate_and_upload_keys(force_regen=True)
                    return
                except Exception as e:
                    logger.debug(
                        f"[E2EE-CrossSign] 重新生成交叉签名密钥失败：{e}"
                    )
                    logger.debug(
                        "[E2EE-CrossSign] 将继续使用服务器现有的密钥"
                        "（交叉签名可能无法正常工作）"
                    )

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

    def _b64_optional(self, data: bytes | None) -> str | None:
        if data is None:
            return None
        return self._b64(data)

    def _canonical(self, obj: dict) -> str:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

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

    def _derive_public_key(self, priv_raw: bytes) -> str | None:
        """从私钥推导出公钥（unpadded base64）"""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            priv = Ed25519PrivateKey.from_private_bytes(priv_raw)
            pub_raw = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return self._b64(pub_raw)
        except Exception:
            return None

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
                    logger.debug(
                        f"[E2EE-CrossSign] 本地 {name} 私钥与服务器公钥不匹配"
                    )
                    return False
        return True

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

    async def _upload_signature_and_confirm(
        self,
        upload_payload: dict,
        verify,
        failure_context: str,
    ) -> bool:
        upload_response = await self.client.upload_signatures(signatures=upload_payload)
        failures = upload_response.get("failures") if isinstance(upload_response, dict) else None
        if isinstance(failures, dict) and failures:
            logger.warning(
                f"[E2EE-CrossSign] {failure_context}上传被服务器拒绝：failures={failures}"
            )
            return False

        for _ in range(5):
            if await verify():
                return True
            await asyncio.sleep(1.0)

        logger.warning(f"[E2EE-CrossSign] {failure_context}未在服务器状态中出现")
        return False

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

        try:
            await self.client.upload_signing_keys(
                master_key=master_key,
                self_signing_key=self_signing_key,
                user_signing_key=user_signing_key,
            )
        except MatrixAPIError as e:
            auth_data = getattr(e, "data", {}) if isinstance(e.data, dict) else {}
            if self.password and auth_data.get("session"):
                auth_payload = {
                    "type": "m.login.password",
                    "user": self.user_id,
                    "password": self.password,
                    "session": auth_data.get("session"),
                }
                await self.client.upload_signing_keys(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth=auth_payload,
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

    async def sign_device(self, device_id: str) -> bool:
        if not self._self_signing_priv or not self._self_signing_key:
            logger.debug("[E2EE-CrossSign] self-signing key 不可用，跳过设备签名")
            return False
        try:
            response = await self.client.query_keys({self.user_id: [device_id]})
            device_keys = (
                (response.get("device_keys") or {}).get(self.user_id, {}).get(device_id)
            )
            if not device_keys:
                logger.debug("[E2EE-CrossSign] 未找到设备密钥，无法签名")
                return False

            device_keys.pop("unsigned", None)
            signing_key_id = f"ed25519:{self._self_signing_key}"
            sig = self._sign(self._self_signing_priv, device_keys)
            existing_signatures = device_keys.get("signatures")
            if not isinstance(existing_signatures, dict):
                existing_signatures = {}
            user_signatures = existing_signatures.get(self.user_id)
            if not isinstance(user_signatures, dict):
                user_signatures = {}
            user_signatures[signing_key_id] = sig
            existing_signatures[self.user_id] = user_signatures
            device_keys["signatures"] = existing_signatures

            async def _verify_uploaded_device_signature() -> bool:
                refreshed = await self.client.query_keys({self.user_id: [device_id]})
                refreshed_device_keys = (
                    (refreshed.get("device_keys") or {}).get(self.user_id, {}).get(device_id)
                    or {}
                )
                refreshed_signatures = (
                    (refreshed_device_keys.get("signatures") or {}).get(self.user_id, {})
                )
                return signing_key_id in refreshed_signatures

            upload_payload = {self.user_id: {device_id: device_keys}}
            ok = await self._upload_signature_and_confirm(
                upload_payload,
                _verify_uploaded_device_signature,
                f"设备签名 device={device_id} ",
            )
            if not ok:
                return False

            logger.debug(f"[E2EE-CrossSign] 已签名设备：{device_id}")
            return True
        except MatrixAPIError as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名失败：{e}")
            return False
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 设备签名异常：{e}")
            return False

    async def sign_master_key_with_device(self, user_id: str | None = None) -> bool:
        target_user_id = user_id or self.user_id
        if target_user_id != self.user_id:
            logger.debug("[E2EE-CrossSign] 仅支持为当前账号的 master key 添加设备签名")
            return False
        if not self.olm or not self._master_key:
            logger.debug("[E2EE-CrossSign] master key 或 olm 账户不可用，跳过设备签名 master key")
            return False

        try:
            response = await self.client.query_keys({target_user_id: []})
            master_key = (response.get("master_keys") or {}).get(target_user_id)
            if not master_key:
                logger.debug("[E2EE-CrossSign] 未找到 master key，无法添加设备签名")
                return False

            usage = master_key.get("usage")
            keys = master_key.get("keys")
            if not isinstance(usage, list) or not isinstance(keys, dict) or not keys:
                logger.debug("[E2EE-CrossSign] master key 结构无效，无法添加设备签名")
                return False
            master_key_id, master_key_value = next(iter(keys.items()))

            signable_master_key = {
                "user_id": target_user_id,
                "usage": list(usage),
                "keys": {master_key_id: master_key_value},
            }
            canonical_json = self._canonical(signable_master_key)
            canonical_bytes = canonical_json.encode("utf-8")
            signature = self.olm._account.sign(canonical_bytes).to_base64()
            signing_key_id = self.device_key_id
            device_ed25519_pub = self.olm._account.ed25519_key.to_base64()

            # 诊断日志：记录签名的详细信息
            logger.warning(
                "[E2EE-CrossSign] 签名诊断信息：\n"
                f"  canonical_json={canonical_json}\n"
                f"  device_ed25519_pub={device_ed25519_pub}\n"
                f"  signing_key_id={signing_key_id}\n"
                f"  device_id(olm)={self.olm.device_id}\n"
                f"  device_id(self)={self.device_id}\n"
                f"  signature={signature}"
            )

            # 本地验证签名
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PublicKey,
                )

                pub_b64 = device_ed25519_pub
                padding = 4 - len(pub_b64) % 4
                if padding != 4:
                    pub_b64 += "=" * padding
                pub_bytes = base64.b64decode(pub_b64)
                pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

                sig_b64 = signature
                sig_padding = 4 - len(sig_b64) % 4
                if sig_padding != 4:
                    sig_b64 += "=" * sig_padding
                sig_bytes = base64.b64decode(sig_b64)

                pub_key.verify(sig_bytes, canonical_bytes)
                logger.warning("[E2EE-CrossSign] ✅ 本地签名验证成功")
            except Exception as verify_err:
                logger.warning(
                    f"[E2EE-CrossSign] ❌ 本地签名验证失败：{verify_err}"
                )

            # 查询服务器上的设备密钥，对比 ed25519 公钥
            try:
                dev_response = await self.client.query_keys(
                    {target_user_id: [self.device_id]}
                )
                server_device_keys = (
                    (dev_response.get("device_keys") or {})
                    .get(target_user_id, {})
                    .get(self.device_id)
                )
                if server_device_keys:
                    server_ed25519 = (
                        server_device_keys.get("keys", {})
                        .get(f"ed25519:{self.device_id}")
                    )
                    logger.warning(
                        "[E2EE-CrossSign] 服务器设备 ed25519 对比：\n"
                        f"  server={server_ed25519}\n"
                        f"  local ={device_ed25519_pub}\n"
                        f"  match ={server_ed25519 == device_ed25519_pub}"
                    )
                else:
                    logger.warning(
                        f"[E2EE-CrossSign] 服务器上未找到设备 {self.device_id} 的密钥！"
                    )
            except Exception as query_err:
                logger.warning(
                    f"[E2EE-CrossSign] 查询设备密钥失败：{query_err}"
                )

            upload_master_key = {
                "user_id": target_user_id,
                "usage": list(usage),
                "keys": {master_key_id: master_key_value},
                "signatures": {target_user_id: {signing_key_id: signature}},
            }

            async def _verify_uploaded_master_signature() -> bool:
                refreshed = await self.client.query_keys({target_user_id: []})
                refreshed_master_key = (
                    (refreshed.get("master_keys") or {}).get(target_user_id) or {}
                )
                refreshed_signatures = (
                    (refreshed_master_key.get("signatures") or {}).get(target_user_id, {})
                )
                return signing_key_id in refreshed_signatures

            logger.debug(
                "[E2EE-CrossSign] 上传 master key 设备签名："
                f"master={master_key_id} signer={signing_key_id}"
            )
            ok = await self._upload_signature_and_confirm(
                {target_user_id: {master_key_id: upload_master_key}},
                _verify_uploaded_master_signature,
                "master key 设备签名 ",
            )
            if not ok:
                return False

            logger.debug("[E2EE-CrossSign] 已为 master key 添加设备签名")
            return True
        except MatrixAPIError as e:
            logger.warning(f"[E2EE-CrossSign] master key 设备签名失败：{e}")
            return False
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] master key 设备签名异常：{e}")
            return False

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
        key_id = next(iter(keys))

        # /keys/signatures/upload 请求格式：{"signatures": {user_id: {key_id: master_key}}}
        await self.client.upload_signatures(
            signatures={target_user_id: {key_id: master_key}}
        )
        logger.debug(f"[E2EE-CrossSign] 已验证用户：{target_user_id}")
