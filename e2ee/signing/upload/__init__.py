"""Composable cross-signing upload operations."""

import asyncio
import copy

from astrbot.api import logger

from ....client.http_client import MatrixAPIError
from ....constants import LOGIN_TYPE_DUMMY
from ...backup.crypto_utils import CRYPTO_AVAILABLE
from .devices import CrossSigningUploadDevicesMixin
from .generation import CrossSigningUploadGenerationMixin
from .signatures import CrossSigningUploadSignaturesMixin
from .uia import CrossSigningUploadUIAMixin


class CrossSigningUploadMixin(
    CrossSigningUploadUIAMixin,
    CrossSigningUploadDevicesMixin,
    CrossSigningUploadSignaturesMixin,
    CrossSigningUploadGenerationMixin,
):
    """生成与上传密钥"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in ("_upload_signing_keys_with_uia",):
    setattr(
        CrossSigningUploadMixin,
        _method_name,
        getattr(CrossSigningUploadUIAMixin, _method_name),
    )

for _method_name in (
    "_repair_current_device_keys_once",
    "_republish_current_device_keys",
):
    setattr(
        CrossSigningUploadMixin,
        _method_name,
        getattr(CrossSigningUploadDevicesMixin, _method_name),
    )

CrossSigningUploadMixin._upload_signature_and_confirm = (
    CrossSigningUploadSignaturesMixin._upload_signature_and_confirm
)

for _method_name in ("_generate_and_upload_keys", "upload_cross_signing_keys"):
    setattr(
        CrossSigningUploadMixin,
        _method_name,
        getattr(CrossSigningUploadGenerationMixin, _method_name),
    )


__all__ = [
    "CRYPTO_AVAILABLE",
    "CrossSigningUploadDevicesMixin",
    "CrossSigningUploadGenerationMixin",
    "CrossSigningUploadMixin",
    "CrossSigningUploadSignaturesMixin",
    "CrossSigningUploadUIAMixin",
    "LOGIN_TYPE_DUMMY",
    "MatrixAPIError",
    "asyncio",
    "copy",
    "logger",
]
