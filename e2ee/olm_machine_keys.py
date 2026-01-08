import json
from typing import Any

from astrbot.api import logger

from ..constants import (
    DEFAULT_ONE_TIME_KEYS_COUNT,
    MEGOLM_ALGO,
    OLM_ALGO,
)


class OlmMachineKeysMixin:
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

        device_keys_json = self._canonical_json(payload_to_sign)
        signature = self._account.sign(device_keys_json.encode()).to_base64()

        device_keys["signatures"] = {
            self.user_id: {f"ed25519:{self.device_id}": signature}
        }

        return device_keys

    def generate_one_time_keys(
        self, count: int = DEFAULT_ONE_TIME_KEYS_COUNT
    ) -> dict[str, dict]:
        """
        生成一次性密钥

        Args:
            count: 要生成的密钥数量

        Returns:
            签名的一次性密钥字典
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        # 生成新的一次性密钥
        self._account.generate_one_time_keys(count)

        # 获取一次性密钥
        one_time_keys = self._account.one_time_keys

        # 签名每个密钥 (key 是 Curve25519PublicKey 对象，需要转为字符串)
        signed_keys = {}
        for key_id, key in one_time_keys.items():
            key_str = key.to_base64()  # 转换为字符串
            signed_key = {
                "key": key_str,
            }

            # 生成签名 (vodozemac sign 需要 bytes 输入)
            key_json = self._canonical_json(signed_key)
            signature = self._account.sign(key_json.encode()).to_base64()
            signed_key["signatures"] = {
                self.user_id: {f"ed25519:{self.device_id}": signature}
            }

            # 标记为已签名的 curve25519
            signed_keys[f"signed_curve25519:{key_id}"] = signed_key

        return signed_keys

    def mark_keys_as_published(self):
        """标记一次性密钥为已发布"""
        if self._account:
            self._account.mark_keys_as_published()
            self._save_account()

    def generate_fallback_key(self) -> dict[str, dict]:
        """
        生成 fallback key（备用密钥）

        Fallback key 是一个特殊的密钥，当一次性密钥用尽时可以使用。
        与一次性密钥不同，fallback key 可以被多次使用。

        Returns:
            签名的 fallback key 字典
        """
        if not self._account:
            raise RuntimeError("Olm 账户未初始化")

        # 生成新的 fallback key
        self._account.generate_fallback_key()

        # 获取 fallback key
        fallback_key = self._account.fallback_key

        if not fallback_key:
            logger.warning("没有可用的 fallback key")
            return {}

        # 签名 fallback key
        signed_keys = {}
        for key_id, key in fallback_key.items():
            key_str = key.to_base64()
            signed_key = {
                "key": key_str,
                "fallback": True,  # 标记为 fallback key
            }

            # 生成签名
            key_json = self._canonical_json(signed_key)
            signature = self._account.sign(key_json.encode()).to_base64()
            signed_key["signatures"] = {
                self.user_id: {f"ed25519:{self.device_id}": signature}
            }

            signed_keys[f"signed_curve25519:{key_id}"] = signed_key

        logger.info(f"生成了 {len(signed_keys)} 个 fallback key")
        return signed_keys

    def get_unpublished_fallback_key_count(self) -> int:
        """获取未发布的 fallback key 数量"""
        if not self._account:
            return 0
        # vodozemac 的 fallback_key 属性返回未标记为已发布的 fallback key
        return len(self._account.fallback_key) if self._account.fallback_key else 0

    # ========== Olm 会话 ==========

    @staticmethod
    def _canonical_json(obj: dict) -> str:
        """生成规范化的 JSON 字符串 (用于签名)"""
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

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
