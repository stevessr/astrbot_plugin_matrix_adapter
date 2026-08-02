"""One-time and fallback key generation helpers."""

from astrbot.api import logger

from ....constants import DEFAULT_ONE_TIME_KEYS_COUNT
from ...verification.crypto_utils import _canonical_json


class OlmMachineOneTimeKeysMixin:
    """一次性密钥、fallback key 生成与发布状态管理能力。"""

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
            key_json = _canonical_json(signed_key)
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
            self._is_new_account = False
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
            key_json = _canonical_json(signed_key)
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
