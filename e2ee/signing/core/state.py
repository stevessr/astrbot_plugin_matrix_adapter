"""Local key state and public properties for cross-signing."""


class CrossSigningCoreStateMixin:
    """交叉签名密钥状态与公开属性。"""

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

    @staticmethod
    def _json_filename_resolver(_: str) -> str:
        return "cross_signing.json"
