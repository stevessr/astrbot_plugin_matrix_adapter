"""Recovery-key Base64 decoding helper."""

import base64

from .....constants import (
    RECOVERY_KEY_HDR_BYTE1,
    RECOVERY_KEY_HDR_BYTE2,
    RECOVERY_KEY_PRIV_LEN,
    RECOVERY_KEY_TOTAL_LEN,
)


def _decode_recovery_key_base64(key_str: str) -> bytes:
    """Decode a Base64-encoded recovery key; raises on failure."""
    decoded = base64.b64decode(key_str + "===")

    if (
        len(decoded) >= RECOVERY_KEY_TOTAL_LEN
        and decoded[0] == RECOVERY_KEY_HDR_BYTE1
        and decoded[1] == RECOVERY_KEY_HDR_BYTE2
    ):
        checksum = 0
        for b in decoded[:-1]:
            checksum ^= b
        if checksum != decoded[-1]:
            raise ValueError("Base64 恢复密钥校验失败 (XOR mismatch)")
        return decoded[2 : 2 + RECOVERY_KEY_PRIV_LEN]

    if len(decoded) >= RECOVERY_KEY_PRIV_LEN:
        return decoded[:RECOVERY_KEY_PRIV_LEN]

    raise ValueError("Base64 解码失败")


__all__ = ["_decode_recovery_key_base64"]
