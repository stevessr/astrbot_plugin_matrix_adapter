import base64
import hashlib
import hmac


SAS_MAC_V2 = "hkdf-hmac-sha256.v2"
SAS_MAC_LEGACY = "hkdf-hmac-sha256"


def _compute_hkdf(
    input_key: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32,
) -> bytes:
    """计算 HKDF-SHA256。"""
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, input_key, hashlib.sha256).digest()

    output = b""
    t = b""
    counter = 1
    while len(output) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        output += t
        counter += 1
    return output[:length]


def _compute_sas_mac_v2(shared_secret: bytes, message: str, info: str) -> bytes:
    """Compute stable Matrix ``hkdf-hmac-sha256.v2`` before Base64 encoding."""
    if not isinstance(shared_secret, (bytes, bytearray)) or not shared_secret:
        raise ValueError("shared_secret must be non-empty bytes")
    if not isinstance(message, str):
        raise TypeError("message must be a string")
    if not isinstance(info, str) or not info:
        raise ValueError("info must be a non-empty string")

    mac_key = _compute_hkdf(bytes(shared_secret), b"", info.encode("utf-8"), 32)
    return hmac.new(mac_key, message.encode("utf-8"), hashlib.sha256).digest()


def _calculate_sas_mac(
    *,
    method: str,
    message: str,
    info: str,
    established_sas=None,
    shared_secret: bytes | None = None,
) -> str:
    """Calculate a negotiated SAS MAC without silently changing algorithms.

    ``hkdf-hmac-sha256.v2`` uses correct unpadded Matrix Base64. The deprecated
    libolm-compatible method is only used when the crypto backend explicitly
    exposes ``calculate_mac_invalid_base64``; reproducing that historical bug
    with an unrelated fallback would make verification unsafe and unreliable.
    """
    if method == SAS_MAC_V2:
        if established_sas is not None:
            return str(established_sas.calculate_mac(message, info))
        if shared_secret is None:
            raise ValueError("shared_secret is required without established_sas")
        raw = _compute_sas_mac_v2(shared_secret, message, info)
        return base64.b64encode(raw).decode("ascii").rstrip("=")

    if method == SAS_MAC_LEGACY:
        legacy = getattr(established_sas, "calculate_mac_invalid_base64", None)
        if callable(legacy):
            return str(legacy(message, info))
        raise RuntimeError(
            "legacy hkdf-hmac-sha256 requires a libolm-compatible SAS backend"
        )

    raise ValueError(f"unsupported SAS MAC method: {method}")
