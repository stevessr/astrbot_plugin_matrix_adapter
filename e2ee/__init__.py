"""
Matrix E2EE (End-to-End Encryption) Module

提供 Matrix 端到端加密支持，使用 vodozemac 实现 Olm/Megolm 协议。

警告：这是试验性功能，需要充分测试后才能用于生产环境。
"""

from .crypto_store import CryptoStore
from .e2ee_manager import E2EEManager
from .key_backup import CrossSigning, KeyBackup
from .olm_machine import VODOZEMAC_AVAILABLE, OlmMachine
from .verification import SASVerification

__all__ = [
    "OlmMachine",
    "CryptoStore",
    "E2EEManager",
    "VODOZEMAC_AVAILABLE",
    "SASVerification",
    "KeyBackup",
    "CrossSigning",
]
