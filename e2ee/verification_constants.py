from astrbot.api import logger

from .constants import (
    HASHES,
    MESSAGE_AUTHENTICATION_CODES,
    SAME_USER_QR_METHODS,
    SAS_EMOJIS,
    SAS_METHODS,
    SHORT_AUTHENTICATION_STRING,
)

__all__ = [
    "HASHES",
    "MESSAGE_AUTHENTICATION_CODES",
    "SAME_USER_QR_METHODS",
    "SAS_EMOJIS",
    "SAS_METHODS",
    "SHORT_AUTHENTICATION_STRING",
]

# 尝试导入 vodozemac
try:
    from vodozemac import Curve25519PublicKey, EstablishedSas, Sas  # noqa: F401

    VODOZEMAC_SAS_AVAILABLE = True
except ImportError:
    Curve25519PublicKey = None
    EstablishedSas = None
    Sas = None
    VODOZEMAC_SAS_AVAILABLE = False
    logger.debug("vodozemac SAS 模块不可用，将使用简化实现")
