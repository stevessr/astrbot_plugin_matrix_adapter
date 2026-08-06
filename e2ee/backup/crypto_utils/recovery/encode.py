"""Recovery-key Base58 encoding helper."""

from .....constants import (
    BASE58_ALPHABET,
    RECOVERY_KEY_HDR_BYTE1,
    RECOVERY_KEY_HDR_BYTE2,
    RECOVERY_KEY_PRIV_LEN,
)


def _encode_recovery_key(key_bytes: bytes) -> str:
    """
    将 32 字节密钥编码为 Matrix 恢复密钥 (Base58)
    """
    if len(key_bytes) != RECOVERY_KEY_PRIV_LEN:
        raise ValueError("恢复密钥长度必须为 32 字节")

    data = bytearray()
    data.append(RECOVERY_KEY_HDR_BYTE1)
    data.append(RECOVERY_KEY_HDR_BYTE2)
    data.extend(key_bytes)

    checksum = 0
    for b in data:
        checksum ^= b
    data.append(checksum)

    # Base58 编码
    value = int.from_bytes(data, "big")
    encoded = ""
    while value > 0:
        value, rem = divmod(value, 58)
        encoded = BASE58_ALPHABET[rem] + encoded

    # 补前导零
    for b in data:
        if b == 0:
            encoded = BASE58_ALPHABET[0] + encoded
        else:
            break

    # 每 4 字符插入空格（可读格式）
    groups = [encoded[i : i + 4] for i in range(0, len(encoded), 4)]
    return " ".join(groups)


__all__ = ["_encode_recovery_key"]
