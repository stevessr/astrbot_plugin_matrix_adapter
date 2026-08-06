"""Recovery-key Base58 decoding helper."""

from .....constants import (
    BASE58_ALPHABET,
    RECOVERY_KEY_HDR_BYTE1,
    RECOVERY_KEY_HDR_BYTE2,
    RECOVERY_KEY_PRIV_LEN,
    RECOVERY_KEY_TOTAL_LEN,
)


def _decode_recovery_key_base58(key_str: str) -> bytes:
    """Decode a Base58-encoded recovery key; raises on failure."""
    value = 0
    for c in key_str:
        value = value * 58 + BASE58_ALPHABET.index(c)

    decoded = value.to_bytes(RECOVERY_KEY_TOTAL_LEN, "big")
    if (
        len(decoded) != RECOVERY_KEY_TOTAL_LEN
        or decoded[0] != RECOVERY_KEY_HDR_BYTE1
        or decoded[1] != RECOVERY_KEY_HDR_BYTE2
    ):
        raise ValueError("恢复密钥头部不匹配，应为 0x8B01")

    checksum = 0
    for b in decoded[:-1]:
        checksum ^= b
    if checksum != decoded[-1]:
        raise ValueError("恢复密钥校验失败 (XOR mismatch)")

    private_key = decoded[2 : 2 + RECOVERY_KEY_PRIV_LEN]
    return private_key


__all__ = ["_decode_recovery_key_base58"]
