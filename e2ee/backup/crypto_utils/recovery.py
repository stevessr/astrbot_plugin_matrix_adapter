"""Matrix recovery-key Base58/Base64 encoding and decoding helpers."""

import base64

from astrbot.api import logger

from ....constants import (
    BASE58_ALPHABET,
    RECOVERY_KEY_HDR_BYTE1,
    RECOVERY_KEY_HDR_BYTE2,
    RECOVERY_KEY_PRIV_LEN,
    RECOVERY_KEY_TOTAL_LEN,
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


def _decode_recovery_key(key_str: str) -> bytes:
    """
    解析 Matrix 恢复密钥 (Base58 或 Base64)
    """
    key_str = key_str.replace(" ", "")

    # 尝试 Base58（标准恢复密钥格式）
    try:
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
    except Exception as e:
        logger.debug(f"Base58 恢复密钥解析失败：{e}")

    # 尝试 Base64（兼容旧格式或直接私钥字符串）
    try:
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
    except Exception:
        logger.debug("Base64 解码失败，尝试其他格式")

    raise ValueError("无法解码恢复密钥，请检查输入格式（应为 Matrix Base58 或 Base64）")
