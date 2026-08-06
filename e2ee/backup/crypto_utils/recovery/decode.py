"""Matrix recovery-key Base58/Base64 decoding orchestrator."""

from astrbot.api import logger

from .base58 import _decode_recovery_key_base58
from .base64 import _decode_recovery_key_base64


def _decode_recovery_key(key_str: str) -> bytes:
    """
    解析 Matrix 恢复密钥 (Base58 或 Base64)
    """
    key_str = key_str.replace(" ", "")

    # 尝试 Base58（标准恢复密钥格式）
    try:
        return _decode_recovery_key_base58(key_str)
    except Exception as e:
        logger.debug(f"Base58 恢复密钥解析失败：{e}")

    # 尝试 Base64（兼容旧格式或直接私钥字符串）
    try:
        return _decode_recovery_key_base64(key_str)
    except Exception:
        logger.debug("Base64 解码失败，尝试其他格式")

    raise ValueError("无法解码恢复密钥，请检查输入格式（应为 Matrix Base58 或 Base64）")


__all__ = ["_decode_recovery_key"]
