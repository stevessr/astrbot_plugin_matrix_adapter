"""
E2EE Secrets Crypto Mixin - 秘密共享相关的加密与设备密钥管理

提供 to-device 加密、设备密钥获取/校验、待处理请求管理等底层能力，
被 E2EEManagerSecretsHandlersMixin 通过 MRO 调用。

参考：https://spec.matrix.org/latest/client-server-api/#sharing-keys-between-devices
"""

from astrbot.api import logger

from ....constants import SIGNED_CURVE25519
from .device import E2EEManagerSecretsDeviceMixin
from .encryption import E2EEManagerSecretsEncryptionMixin
from .requests import E2EEManagerSecretsRequestsMixin


class E2EEManagerSecretsCryptoMixin(
    E2EEManagerSecretsEncryptionMixin,
    E2EEManagerSecretsDeviceMixin,
    E2EEManagerSecretsRequestsMixin,
):
    """秘密共享相关的加密与设备密钥管理 Mixin"""

    pass


# Keep the former monolithic mixin's methods in the combined class namespace.
# Static methods are re-wrapped so descriptor behavior remains unchanged.
E2EEManagerSecretsCryptoMixin._mask_device_id = staticmethod(
    E2EEManagerSecretsDeviceMixin._mask_device_id
)
E2EEManagerSecretsCryptoMixin._mask_request_id = staticmethod(
    E2EEManagerSecretsRequestsMixin._mask_request_id
)
E2EEManagerSecretsCryptoMixin._encrypt_to_device = (
    E2EEManagerSecretsEncryptionMixin._encrypt_to_device
)
E2EEManagerSecretsCryptoMixin._get_validated_device_info = (
    E2EEManagerSecretsDeviceMixin._get_validated_device_info
)
E2EEManagerSecretsCryptoMixin._get_pending_secret_request = (
    E2EEManagerSecretsRequestsMixin._get_pending_secret_request
)
E2EEManagerSecretsCryptoMixin._remove_pending_secret_request = (
    E2EEManagerSecretsRequestsMixin._remove_pending_secret_request
)
E2EEManagerSecretsCryptoMixin._add_pending_secret_request = (
    E2EEManagerSecretsRequestsMixin._add_pending_secret_request
)
E2EEManagerSecretsCryptoMixin._get_own_devices = (
    E2EEManagerSecretsDeviceMixin._get_own_devices
)
E2EEManagerSecretsCryptoMixin._ensure_device_keys = (
    E2EEManagerSecretsDeviceMixin._ensure_device_keys
)


__all__ = [
    "E2EEManagerSecretsCryptoMixin",
    "E2EEManagerSecretsDeviceMixin",
    "E2EEManagerSecretsEncryptionMixin",
    "E2EEManagerSecretsRequestsMixin",
    "SIGNED_CURVE25519",
    "logger",
]
