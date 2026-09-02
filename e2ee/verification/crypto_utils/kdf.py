import hashlib
import hmac


def _compute_hkdf(
    input_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """计算 HKDF-SHA256。"""
    # HKDF-Extract. RFC 5869 treats an omitted salt as HashLen zero bytes.
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, input_key, hashlib.sha256).digest()

    # HKDF-Expand
    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]


def _compute_sas_mac_v2(shared_secret: bytes, message: str, info: str) -> bytes:
    """Compute the stable ``hkdf-hmac-sha256.v2`` SAS MAC.

    Matrix v1.6 / MSC3783 derives a 32-byte HMAC key from the established SAS
    shared secret with HKDF-SHA256, no salt, and the complete MAC info string.
    The public key (or sorted comma-separated key-id list) is then MACed with
    HMAC-SHA256.  Encoding is intentionally left to the caller so all paths use
    the repository's unpadded Matrix base64 helper.
    """
    if not isinstance(shared_secret, (bytes, bytearray)) or not shared_secret:
        raise ValueError("shared_secret must be non-empty bytes")
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    if not isinstance(info, str) or not info:
        raise ValueError("info must be a non-empty string")

    mac_key = _compute_hkdf(bytes(shared_secret), b"", info.encode("utf-8"), 32)
    return hmac.new(mac_key, message.encode("utf-8"), hashlib.sha256).digest()
