import base64
import copy
import json

from astrbot.api import logger

from ...client.http_client import MatrixAPIError
from ...constants import LOGIN_TYPE_PASSWORD


class CrossSigningCryptoMixin:
    """纯密码学/编码辅助：base64、canonical JSON、ed25519 签名与密钥推导"""

    def _b64(self, data: bytes) -> str:
        return base64.b64encode(data).decode().rstrip("=")

    def _b64_optional(self, data: bytes | None) -> str | None:
        if data is None:
            return None
        return self._b64(data)

    def _canonical(self, obj: dict) -> str:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

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

    def _sign_device_object(self, payload: dict) -> str:
        payload_to_sign = copy.deepcopy(payload)
        payload_to_sign.pop("signatures", None)
        payload_to_sign.pop("unsigned", None)
        canonical = self._canonical(payload_to_sign)
        logger.debug(f"[E2EE-CrossSign] _sign_device_object 规范化 JSON：{canonical}")
        signature = self.olm._account.sign(canonical.encode("utf-8")).to_base64()
        logger.debug(f"[E2EE-CrossSign] _sign_device_object 签名：{signature}")

        # 本地验证签名（使用 nacl，与 Synapse 服务器相同逻辑）
        try:
            import nacl.signing

            ed25519_pub_b64 = getattr(self.olm, "ed25519_key", "")
            pub_bytes = base64.b64decode(
                ed25519_pub_b64 + "=" * (3 - (len(ed25519_pub_b64) + 3) % 4)
            )
            sig_bytes = base64.b64decode(
                signature + "=" * (3 - (len(signature) + 3) % 4)
            )
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

    def _build_password_auth(self, session_id: str) -> dict:
        return {
            "type": LOGIN_TYPE_PASSWORD,
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
