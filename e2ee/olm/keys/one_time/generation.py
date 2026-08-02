"""Signed one-time-key generation."""

from .....constants import DEFAULT_ONE_TIME_KEYS_COUNT
from ....verification.crypto_utils import _canonical_json


class OlmMachineOneTimeKeyGenerationMixin:
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
