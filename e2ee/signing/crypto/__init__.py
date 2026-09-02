"""Composable cross-signing cryptography and identity helpers."""

import base64
import copy
import json

from astrbot.api import logger

from ....client.http_client import MatrixAPIError
from ....constants import LOGIN_TYPE_PASSWORD
from .auth import CrossSigningCryptoAuthMixin
from .encoding import CrossSigningCryptoEncodingMixin
from .identity import CrossSigningCryptoIdentityMixin
from .signing import CrossSigningCryptoSigningMixin


class CrossSigningCryptoMixin(
    CrossSigningCryptoEncodingMixin,
    CrossSigningCryptoIdentityMixin,
    CrossSigningCryptoSigningMixin,
    CrossSigningCryptoAuthMixin,
):
    """纯密码学/编码辅助：base64、canonical JSON、ed25519 签名与密钥推导"""

    pass


# Preserve direct method attributes exposed by the former monolithic module.
for _method_name in (
    "_b64",
    "_b64_optional",
    "_canonical",
    "_decode_secret_bytes",
    "_gen_keypair",
    "_derive_public_key",
):
    setattr(
        CrossSigningCryptoMixin,
        _method_name,
        getattr(CrossSigningCryptoEncodingMixin, _method_name),
    )

for _method_name in (
    "_local_keys_match_server",
    "_get_local_device_identity_keys",
    "_current_device_matches_server",
):
    setattr(
        CrossSigningCryptoMixin,
        _method_name,
        getattr(CrossSigningCryptoIdentityMixin, _method_name),
    )

CrossSigningCryptoMixin._extract_device_identity = staticmethod(
    CrossSigningCryptoIdentityMixin.__dict__["_extract_device_identity"].__func__
)

for _method_name in ("_sign", "_sign_device_object"):
    setattr(
        CrossSigningCryptoMixin,
        _method_name,
        getattr(CrossSigningCryptoSigningMixin, _method_name),
    )

CrossSigningCryptoMixin._build_password_auth = (
    CrossSigningCryptoAuthMixin._build_password_auth
)
# ``_extract_uia_session`` became a classmethod when OAuth UIA parsing started
# sharing the same extractor.  Preserve that descriptor here: wrapping its
# ``__func__`` as a staticmethod drops the implicit class argument and breaks
# the legacy CrossSigningCryptoMixin aggregation surface.
CrossSigningCryptoMixin._extract_uia_session = classmethod(
    CrossSigningCryptoAuthMixin.__dict__["_extract_uia_session"].__func__
)


__all__ = [
    "CrossSigningCryptoAuthMixin",
    "CrossSigningCryptoEncodingMixin",
    "CrossSigningCryptoIdentityMixin",
    "CrossSigningCryptoMixin",
    "CrossSigningCryptoSigningMixin",
    "LOGIN_TYPE_PASSWORD",
    "MatrixAPIError",
    "base64",
    "copy",
    "json",
    "logger",
]
