import asyncio
import base64
import copy
import json
from pathlib import Path
from typing import Awaitable, Callable

from astrbot.api import logger

from ..client.http_client import MatrixAPIError
from ..constants import (
    SECRET_CROSS_SIGNING_MASTER,
    SECRET_CROSS_SIGNING_SELF_SIGNING,
    SECRET_CROSS_SIGNING_USER_SIGNING,
)
from ..plugin_config import get_plugin_config
from .key_backup_crypto import CRYPTO_AVAILABLE
from .storage import build_e2ee_data_store

# 是否尝试在本地密钥与服务器不一致时强行覆盖服务器的交叉签名密钥。
# 设置为 True 将在以下情况下重新生成并上传新密钥：
#   1. 服务器已有交叉签名密钥，但本地缺少私钥
#   2. 本地私钥推导的公钥与服务器公钥不匹配
# 设置为 False 则仅记录警告，不覆盖服务器密钥。
FORCE_OVERWRITE_SERVER_KEYS = True
DEVICE_SECRET_REQUEST_PENDING = "pending"
DEVICE_SECRET_REQUEST_FAILED = "failed"
DEVICE_SECRET_REQUEST_NOT_NEEDED = "not_needed"
DEVICE_SECRET_REQUEST_UNAVAILABLE = "unavailable"


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
        secret_storage=None,
        request_secret_from_devices: Callable[[str], Awaitable[str | None]] | None = None,
        repair_current_device_keys: Callable[[], Awaitable[None]] | None = None,
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
        self.secret_storage = secret_storage
        self.request_secret_from_devices = request_secret_from_devices
        self.repair_current_device_keys = repair_current_device_keys

        self._master_key: str | None = None
        self._self_signing_key: str | None = None
        self._user_signing_key: str | None = None

        # 私钥（Raw 32B），仅本地持久化
        self._master_priv = None
        self._self_signing_priv = None
        self._user_signing_priv = None
        self._pending_secret_requests: set[str] = set()

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
            (
                server_master,
                server_self_signing,
                server_user_signing,
                keys_need_regen,
            ) = await self._query_server_cross_signing_state()

            if keys_need_regen:
                logger.debug(
                    "[E2EE-CrossSign] 检测到旧格式交叉签名 key ID，准备重新生成"
                )
                await self._generate_and_upload_keys(force_regen=True)
                return

            if server_master:
                local_ready = self._has_private_keys_for_server_state(
                    server_self_signing,
                    server_user_signing,
                )
                local_matches = local_ready and self._local_keys_match_server(
                    server_master,
                    server_self_signing,
                    server_user_signing,
                )

                if not local_matches:
                    restored = await self._restore_private_keys_from_secret_storage(
                        server_master,
                        server_self_signing,
                        server_user_signing,
                    )
                    local_ready = self._has_private_keys_for_server_state(
                        server_self_signing,
                        server_user_signing,
                    )
                    local_matches = local_ready and self._local_keys_match_server(
                        server_master,
                        server_self_signing,
                        server_user_signing,
                    )

                    if not local_matches:
                        request_status = await self._request_missing_private_keys_from_devices(
                            server_master,
                            server_self_signing,
                            server_user_signing,
                        )
                        if request_status == DEVICE_SECRET_REQUEST_PENDING:
                            logger.info(
                                "[E2EE-CrossSign] 已向其他设备请求 cross-signing 私钥，"
                                "等待设备间恢复后再继续"
                            )
                            return

                        overwrite_reason = (
                            "服务器已有交叉签名密钥，但本地缺少对应私钥"
                            if not local_ready
                            else "本地私钥与服务器公钥不匹配（可能已被其他客户端重置）"
                        )
                        if FORCE_OVERWRITE_SERVER_KEYS:
                            logger.warning(
                                f"[E2EE-CrossSign] {overwrite_reason}，恢复路径失败后将重新生成"
                            )
                            await self._generate_and_upload_keys(force_regen=True)
                            return

                        logger.warning(
                            f"[E2EE-CrossSign] {overwrite_reason}."
                            "如需强行覆盖服务器密钥，请将 FORCE_OVERWRITE_SERVER_KEYS 设置为 True"
                        )
                        return

                if server_self_signing and server_user_signing:
                    logger.debug("[E2EE-CrossSign] 交叉签名密钥已就绪")
                    return

                if self._master_priv:
                    try:
                        await self._generate_and_upload_keys(
                            force_regen=False,
                            reuse_master=True,
                        )
                    except Exception as e:
                        logger.warning(f"[E2EE-CrossSign] 补全交叉签名密钥失败：{e}")
                        logger.warning("[E2EE-CrossSign] 部分交叉签名功能可能不可用")
                return

            try:
                await self._generate_and_upload_keys(
                    force_regen=not bool(self._master_priv),
                    reuse_master=bool(self._master_priv),
                )
            except Exception as e:
                logger.warning(f"[E2EE-CrossSign] 生成交叉签名密钥失败：{e}")
                logger.warning("[E2EE-CrossSign] 交叉签名功能将不可用")

        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 初始化失败：{e}")

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

    def _decode_secret_bytes(self, secret_bytes: bytes) -> bytes | None:
        if not secret_bytes:
            return None
        if len(secret_bytes) == 32:
            return secret_bytes
        try:
            secret_str = secret_bytes.decode("utf-8").strip()
        except Exception:
            return None
        if not secret_str:
            return None
        padding = "=" * (-len(secret_str) % 4)
        try:
            decoded = base64.b64decode(secret_str + padding)
        except Exception:
            return None
        if len(decoded) == 32:
            return decoded
        return None

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
                secret_bytes = await self.secret_storage.read_secret_from_secret_storage(
                    secret_name
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
        if (
            server_master
            and (
                not self._master_priv
                or self._derive_public_key(self._master_priv) != server_master
            )
        ):
            missing.append(SECRET_CROSS_SIGNING_MASTER)
        if (
            server_self_signing
            and (
                not self._self_signing_priv
                or self._derive_public_key(self._self_signing_priv) != server_self_signing
            )
        ):
            missing.append(SECRET_CROSS_SIGNING_SELF_SIGNING)
        if (
            server_user_signing
            and (
                not self._user_signing_priv
                or self._derive_public_key(self._user_signing_priv) != server_user_signing
            )
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
                write_ok = await self.secret_storage.write_ssss_secret(secret_name, payload)
            except AttributeError:
                write_ok = await self.secret_storage.write_secret_to_secret_storage(
                    secret_name,
                    payload,
                )
            if not write_ok:
                return False
            wrote_any = True

        return True if wrote_any else None

    def _build_password_auth(self, session_id: str) -> dict:
        return {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": self.user_id},
            "password": self.password,
            "session": session_id,
        }

    @staticmethod
    def _extract_uia_session(error: MatrixAPIError) -> str | None:
        data = getattr(error, "data", None)
        if isinstance(data, dict):
            session = data.get("session")
            return session if isinstance(session, str) and session else None
        return None

    async def _upload_signing_keys_with_uia(
        self,
        *,
        master_key: dict,
        self_signing_key: dict,
        user_signing_key: dict,
    ) -> None:
        try:
            await self.client.upload_signing_keys(
                master_key=master_key,
                self_signing_key=self_signing_key,
                user_signing_key=user_signing_key,
            )
            return
        except MatrixAPIError as first_error:
            session_id = self._extract_uia_session(first_error)
            if not session_id:
                raise

            try:
                await self.client.upload_signing_keys(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth={"type": "m.login.dummy", "session": session_id},
                )
                return
            except MatrixAPIError as dummy_error:
                session_id = self._extract_uia_session(dummy_error) or session_id
                if not self.password:
                    logger.warning(
                        "[E2EE-CrossSign] 上传交叉签名密钥失败（未配置 matrix_password）"
                    )
                    raise

                await self.client.upload_signing_keys(
                    master_key=master_key,
                    self_signing_key=self_signing_key,
                    user_signing_key=user_signing_key,
                    auth=self._build_password_auth(session_id),
                )

    async def _repair_current_device_keys_once(self) -> bool:
        if not self.repair_current_device_keys:
            return False
        try:
            await self.repair_current_device_keys()
            return True
        except Exception as e:
            logger.warning(f"[E2EE-CrossSign] 重新上传当前设备密钥失败：{e}")
            return False

    async def _republish_current_device_keys(self) -> None:
        if not hasattr(self.client, "upload_keys"):
            return
        try:
            response = await self.client.query_keys({self.user_id: [self.device_id]})
            device_keys = (
                (response.get("device_keys") or {})
                .get(self.user_id, {})
                .get(self.device_id)
            )
            if not isinstance(device_keys, dict) or not device_keys:
                return

            republish_payload = copy.deepcopy(device_keys)
            republish_payload.pop("unsigned", None)
            if republish_payload == device_keys:
                logger.debug(
                    "[E2EE-CrossSign] 当前设备 device_keys 已与服务器一致，跳过重复上传"
                )
                return

            await self.client.upload_keys(device_keys=republish_payload)
            logger.debug("[E2EE-CrossSign] 已重发布当前设备的 device_keys 以刷新客户端缓存")
        except Exception as e:
            logger.debug(f"[E2EE-CrossSign] 重发布当前设备 device_keys 失败：{e}")

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

        # 保存旧密钥，以便上传失败时恢复
        old_master_priv = self._master_priv
        old_master_key = self._master_key
        old_self_signing_priv = self._self_signing_priv
        old_self_signing_key = self._self_signing_key
        old_user_signing_priv = self._user_signing_priv
        old_user_signing_key = self._user_signing_key

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
            await self._upload_signing_keys_with_uia(
                master_key=master_key,
                self_signing_key=self_signing_key,
                user_signing_key=user_signing_key,
            )
        except Exception:
            self._restore_keys(
                old_master_priv,
                old_master_key,
                old_self_signing_priv,
                old_self_signing_key,
                old_user_signing_priv,
                old_user_signing_key,
            )
            raise

        self._save_local_keys()
        ssss_status = await self._write_private_keys_to_secret_storage()
        logger.info("[E2EE-CrossSign] 已生成并上传交叉签名密钥")
        if ssss_status is False:
            logger.warning(
                "[E2EE-CrossSign] public cross-signing keys 上传成功，但写入 Secret Storage 失败；"
                "已保留新的本地私钥，不回滚服务器状态"
            )
        elif ssss_status is True:
            logger.info("[E2EE-CrossSign] 已将 cross-signing 私钥写入 Secret Storage")

    def _restore_keys(
        self,
        master_priv, master_key,
        self_signing_priv, self_signing_key,
        user_signing_priv, user_signing_key,
    ):
        """上传失败时恢复旧的密钥状态"""
        self._master_priv = master_priv
        self._master_key = master_key
        self._self_signing_priv = self_signing_priv
        self._self_signing_key = self_signing_key
        self._user_signing_priv = user_signing_priv
        self._user_signing_key = user_signing_key

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
            signing_key_id = f"ed25519:{self._self_signing_key}"
            repaired_current_device = False
            while True:
                response = await self.client.query_keys({self.user_id: [device_id]})
                device_keys = (
                    (response.get("device_keys") or {})
                    .get(self.user_id, {})
                    .get(device_id)
                )
                if not device_keys:
                    if (
                        device_id == self.device_id
                        and not repaired_current_device
                        and await self._repair_current_device_keys_once()
                    ):
                        repaired_current_device = True
                        continue
                    logger.debug("[E2EE-CrossSign] 未找到设备密钥，无法签名")
                    return False

                if device_id != self.device_id:
                    break

                (
                    matches,
                    local_ed25519,
                    local_curve25519,
                    server_ed25519,
                    server_curve25519,
                ) = self._current_device_matches_server(device_keys)
                if matches:
                    break

                if not repaired_current_device and await self._repair_current_device_keys_once():
                    repaired_current_device = True
                    continue

                logger.warning(
                    "[E2EE-CrossSign] 当前设备身份密钥与服务器不一致，跳过设备签名"
                )
                logger.debug(
                    "[E2EE-CrossSign] 设备签名失败细节："
                    f"device_id={device_id} "
                    f"local_ed25519={local_ed25519} server_ed25519={server_ed25519} "
                    f"local_curve25519={local_curve25519} server_curve25519={server_curve25519}"
                )
                return False

            existing_signatures = (
                (device_keys.get("signatures") or {}).get(self.user_id, {}) or {}
            )
            if signing_key_id in existing_signatures:
                logger.debug(
                    f"[E2EE-CrossSign] 设备已存在 owner-sign，跳过重复上传：{device_id}"
                )
                return True

            device_keys_to_upload = copy.deepcopy(device_keys)
            device_keys_to_upload.pop("unsigned", None)
            sig = self._sign(self._self_signing_priv, device_keys_to_upload)
            # 仅包含本次自签名密钥的签名，不携带旧的签名，
            # 避免服务器重新验证旧签名导致 M_INVALID_SIGNATURE。
            device_keys_to_upload["signatures"] = {
                self.user_id: {signing_key_id: sig}
            }

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

            upload_payload = {self.user_id: {device_id: device_keys_to_upload}}
            ok = await self._upload_signature_and_confirm(
                upload_payload,
                _verify_uploaded_device_signature,
                f"设备签名 device={device_id} ",
            )
            if not ok:
                return False

            if device_id == self.device_id:
                await self._republish_current_device_keys()

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
            repaired_current_device = False
            while True:
                response = await self.client.query_keys({target_user_id: []})
                master_key = (response.get("master_keys") or {}).get(target_user_id)
                device_keys = (
                    (response.get("device_keys") or {})
                    .get(target_user_id, {})
                    .get(self.device_id)
                )
                if not master_key:
                    logger.debug("[E2EE-CrossSign] 未找到 master key，无法添加设备签名")
                    return False

                usage = master_key.get("usage")
                keys = master_key.get("keys")
                if not isinstance(usage, list) or not isinstance(keys, dict) or not keys:
                    logger.debug("[E2EE-CrossSign] master key 结构无效，无法添加设备签名")
                    return False

                if not device_keys:
                    if not repaired_current_device and await self._repair_current_device_keys_once():
                        repaired_current_device = True
                        continue
                    logger.warning("[E2EE-CrossSign] 未找到当前设备密钥，无法为 master key 添加设备签名")
                    return False

                (
                    matches,
                    local_ed25519,
                    local_curve25519,
                    server_ed25519,
                    server_curve25519,
                ) = self._current_device_matches_server(device_keys)
                if matches:
                    break

                if not repaired_current_device and await self._repair_current_device_keys_once():
                    repaired_current_device = True
                    continue

                logger.warning(
                    "[E2EE-CrossSign] 当前设备身份密钥与服务器不一致，跳过 master key 设备签名"
                )
                logger.debug(
                    "[E2EE-CrossSign] master key 设备签名失败细节："
                    f"device_id={self.device_id} "
                    f"local_ed25519={local_ed25519} server_ed25519={server_ed25519} "
                    f"local_curve25519={local_curve25519} server_curve25519={server_curve25519}"
                )
                return False

            master_key_id, _master_key_value = next(iter(keys.items()))
            master_pubkey_b64 = _master_key_value

            signing_key_id = self.device_key_id
            existing_signatures = (
                (master_key.get("signatures") or {}).get(target_user_id, {}) or {}
            )
            if signing_key_id in existing_signatures:
                logger.debug(
                    "[E2EE-CrossSign] master key 已存在当前设备签名，跳过重复上传"
                )
                return True

            signature = self._sign_device_object(master_key)
            logger.debug(
                "[E2EE-CrossSign] 签名诊断信息：\n"
                f"  local_device_ed25519={local_ed25519}\n"
                f"  server_device_ed25519={server_ed25519}\n"
                f"  signing_key_id={signing_key_id}\n"
                f"  device_id(olm)={self.olm.device_id}\n"
                f"  device_id(self)={self.device_id}\n"
                f"  master_key_id={master_key_id}\n"
                f"  master_pubkey_b64={master_pubkey_b64}\n"
                f"  signature={signature}"
            )

            master_key_to_upload = copy.deepcopy(master_key)
            master_key_to_upload.pop("unsigned", None)
            # 仅包含本次设备签名，不携带旧的签名。
            # 服务器会重新验证上传载荷中的所有签名，
            # 如果携带了旧的（已失效的）签名会导致 M_INVALID_SIGNATURE。
            master_key_to_upload["signatures"] = {
                target_user_id: {signing_key_id: signature}
            }

            # 验证：上传载荷剥离 signatures/unsigned 后的规范化 JSON
            # 应该与签名时使用的规范化 JSON 完全一致
            verify_payload = copy.deepcopy(master_key_to_upload)
            verify_payload.pop("signatures", None)
            verify_payload.pop("unsigned", None)
            verify_canonical = self._canonical(verify_payload)
            logger.debug(
                f"[E2EE-CrossSign] 上传载荷验证 canonical JSON：{verify_canonical}"
            )

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
                {target_user_id: {master_pubkey_b64: master_key_to_upload}},
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

    def _sign_device_object(self, payload: dict) -> str:
        payload_to_sign = copy.deepcopy(payload)
        payload_to_sign.pop("signatures", None)
        payload_to_sign.pop("unsigned", None)
        canonical = self._canonical(payload_to_sign)
        logger.debug(
            f"[E2EE-CrossSign] _sign_device_object 规范化 JSON：{canonical}"
        )
        signature = self.olm._account.sign(canonical.encode("utf-8")).to_base64()
        logger.debug(
            f"[E2EE-CrossSign] _sign_device_object 签名：{signature}"
        )

        # 本地验证签名（使用 nacl，与 Synapse 服务器相同逻辑）
        try:
            import nacl.signing
            ed25519_pub_b64 = getattr(self.olm, "ed25519_key", "")
            pub_bytes = base64.b64decode(ed25519_pub_b64 + "=" * (3 - (len(ed25519_pub_b64) + 3) % 4))
            sig_bytes = base64.b64decode(signature + "=" * (3 - (len(signature) + 3) % 4))
            verify_key = nacl.signing.VerifyKey(pub_bytes)
            verify_key.verify(canonical.encode("utf-8"), sig_bytes)
            logger.debug(
                f"[E2EE-CrossSign] 本地签名验证通过 ✅ (ed25519_key={ed25519_pub_b64})"
            )
        except Exception as e:
            logger.debug(
                "[E2EE-CrossSign] 本地签名验证失败 ❌："
                f"{e} (ed25519_key={getattr(self.olm, 'ed25519_key', '')})"
            )

        return signature

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
