"""Vodozemac-backed Matrix key-backup decryption."""

import base64

from astrbot.api import logger

from .. import CRYPTO_KEY_SIZE_32
from .manual import _manual_decrypt_v1


def _decrypt_backup_data(
    private_key_bytes: bytes,
    ephemeral_public_key: bytes,
    ciphertext: bytes,
    mac: bytes,
) -> bytes | None:
    """
    解密 Matrix 密钥备份数据 (m.megolm_backup.v1.curve25519-aes-sha2)

    使用 vodozemac 的 PkDecryption 直接解密，它内部处理：
    1. ECDH: 使用私钥和临时公钥计算共享密钥
    2. 密钥派生和 AES 解密
    3. MAC 验证（虽然有已知缺陷）

    Args:
        private_key_bytes: 32 字节私钥
        ephemeral_public_key: 32 字节临时公钥 (来自备份数据的 ephemeral)
        ciphertext: 加密的数据
        mac: MAC 数据

    Returns:
        解密后的明文，或 None
    """
    try:
        from vodozemac import (
            Curve25519SecretKey,
            PkDecryption,
        )

        # Try to import PkDecodeException if available
        try:
            from vodozemac import PkDecodeException  # noqa: F401
        except ImportError:
            pass

        logger.debug(
            f"使用 vodozemac 解密：private_key={len(private_key_bytes)}B, "
            f"ephemeral={len(ephemeral_public_key)}B, ciphertext={len(ciphertext)}B, mac={len(mac)}B"
        )

        if len(ephemeral_public_key) != CRYPTO_KEY_SIZE_32:
            raise ValueError(
                f"ephemeral 公钥长度无效：期望 {CRYPTO_KEY_SIZE_32} 字节，实际 {len(ephemeral_public_key)} 字节"
            )

        # 创建 PkDecryption 对象
        secret_key = Curve25519SecretKey.from_bytes(private_key_bytes)
        pk_decryption = PkDecryption.from_key(secret_key)

        # 创建 Message 对象 - vodozemac 需要特定格式
        # 尝试直接传递字节数据解密
        try:
            # 方法 1: 使用 vodozemac 的内部 Message 格式
            from vodozemac import Message as VodozemacMessage

            # 尝试从 base64 格式创建
            # 参数顺序：from_base64(ciphertext, mac, ephemeral_key)
            ephemeral_key_b64 = base64.b64encode(ephemeral_public_key).decode()
            ciphertext_b64 = base64.b64encode(ciphertext).decode()
            mac_b64 = base64.b64encode(mac).decode()

            # 正确的参数顺序：ciphertext, mac, ephemeral_key
            message = VodozemacMessage.from_base64(
                ciphertext_b64, mac_b64, ephemeral_key_b64
            )
            plaintext = pk_decryption.decrypt(message)

            return plaintext

        except BaseException as e1:
            # 捕获所有异常类型（包括 vodozemac 的特殊异常）
            error_msg = str(e1)
            logger.warning(f"vodozemac 解密失败 ({error_msg})，尝试手动解密...")

            # Fallback to manual decryption
            return _manual_decrypt_v1(
                private_key_bytes, ephemeral_public_key, ciphertext, mac
            )

    except ImportError:
        logger.warning("vodozemac 未安装，使用 Python 原生实现")
        return _manual_decrypt_v1(
            private_key_bytes, ephemeral_public_key, ciphertext, mac
        )
    except Exception as e:
        logger.error(f"初始化 vodozemac 失败：{e}")
        return _manual_decrypt_v1(
            private_key_bytes, ephemeral_public_key, ciphertext, mac
        )
