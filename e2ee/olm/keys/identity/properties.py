"""Current-device identity-key properties."""


class OlmMachineKeyIdentityPropertiesMixin:
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
