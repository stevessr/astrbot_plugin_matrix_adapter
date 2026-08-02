"""Identity and device-key serialization helpers."""

from typing import Any

from ....constants import (
    MEGOLM_ALGO,
    OLM_ALGO,
)
from ...verification.crypto_utils import _canonical_json


class OlmMachineKeyIdentityMixin:
    """设备身份密钥与 Matrix device-keys 对象构造能力。"""

    def get_identity_keys(self) -> dict[str, str]:
        """获取设备身份密钥"""
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        # vodozemac 返回的是 Key 对象，需要转换为字符串
        curve25519 = self._account.curve25519_key.to_base64()
        ed25519 = self._account.ed25519_key.to_base64()

        return {
            f"curve25519:{self.device_id}": curve25519,
            f"ed25519:{self.device_id}": ed25519,
        }

    def get_device_keys(self) -> dict[str, Any]:
        """
        获取用于上传的设备密钥

        返回符合 Matrix 规范的设备密钥格式
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        keys = self.get_identity_keys()

        device_keys = {
            "user_id": self.user_id,
            "device_id": self.device_id,
            # 根据 Matrix 规范，只使用标准算法
            # 参考：https://spec.matrix.org/latest/client-server-api/#device-keys
            "algorithms": [OLM_ALGO, MEGOLM_ALGO],
            "keys": keys,
            # 设备显示名称，帮助用户识别设备
            "unsigned": {
                "device_display_name": "AstrBot",
                "device_id": self.device_id,
            },
        }

        # 生成签名 (vodozemac sign 需要 bytes 输入，返回 Ed25519Signature 对象)
        # 注意：签名时必须排除 unsigned 和 signatures 字段
        payload_to_sign = device_keys.copy()
        payload_to_sign.pop("unsigned", None)
        payload_to_sign.pop("signatures", None)

        device_keys_json = _canonical_json(payload_to_sign)
        signature = self._account.sign(device_keys_json.encode()).to_base64()

        device_keys["signatures"] = {
            self.user_id: {f"ed25519:{self.device_id}": signature}
        }

        return device_keys

    @property
    def curve25519_key(self) -> str:
        """获取本设备的 curve25519 密钥"""
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")
        return self._account.curve25519_key.to_base64()

    @property
    def ed25519_key(self) -> str:
        """获取本设备的 ed25519 密钥"""
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")
        return self._account.ed25519_key.to_base64()
