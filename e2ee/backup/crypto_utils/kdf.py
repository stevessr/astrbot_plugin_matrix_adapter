"""HKDF helpers used by Matrix backup and secret-storage crypto."""

import hashlib
import hmac

from ....constants import CRYPTO_KEY_SIZE_32
from . import CRYPTO_AVAILABLE as _DEFAULT_CRYPTO_AVAILABLE
from . import HKDF as _DEFAULT_HKDF
from . import default_backend as _DEFAULT_DEFAULT_BACKEND
from . import hashes as _DEFAULT_HASHES
from .compat import crypto_available, resolve_attribute


def _compute_hkdf(
    input_key: bytes, salt: bytes, info: bytes, length: int = CRYPTO_KEY_SIZE_32
) -> bytes:
    """计算 HKDF-SHA256"""
    if crypto_available(_DEFAULT_CRYPTO_AVAILABLE):
        hkdf_cls = resolve_attribute("HKDF", _DEFAULT_HKDF)
        hashes_module = resolve_attribute("hashes", _DEFAULT_HASHES)
        backend_factory = resolve_attribute(
            "default_backend",
            _DEFAULT_DEFAULT_BACKEND,
        )
        hkdf = hkdf_cls(
            algorithm=hashes_module.SHA256(),
            length=length,
            salt=salt if salt else None,
            info=info,
            backend=backend_factory(),
        )
        return hkdf.derive(input_key)
    else:
        # 简化的 HKDF 实现
        if not salt:
            salt = b"\x00" * CRYPTO_KEY_SIZE_32
        prk = hmac.new(salt, input_key, hashlib.sha256).digest()
        output = b""
        t = b""
        counter = 1
        while len(output) < length:
            t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
            output += t
            counter += 1
        return output[:length]
