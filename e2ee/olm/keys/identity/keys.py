"""Olm account identity-key serialization."""


class OlmMachineKeyIdentityKeysMixin:
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
