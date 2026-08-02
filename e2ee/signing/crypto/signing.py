"""Cross-signing signature generation helpers."""

import base64
import copy

from astrbot.api import logger


class CrossSigningCryptoSigningMixin:
    """生成 canonical JSON 签名与设备对象签名。"""

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
