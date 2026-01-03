from astrbot.api import logger

# 尝试导入 vodozemac
try:
    from vodozemac import (
        Account,
        AnyOlmMessage,
        Curve25519PublicKey,
        ExportedSessionKey,  # 构造函数接受 base64 字符串
        GroupSession,  # 出站会话 (vodozemac 中称为 GroupSession)
        InboundGroupSession,
        MegolmMessage,  # 解密时需要将密文转换为此类型
        PreKeyMessage,
        Session,
    )

    VODOZEMAC_AVAILABLE = True
except ImportError:
    Account = None
    AnyOlmMessage = None
    Curve25519PublicKey = None
    ExportedSessionKey = None
    GroupSession = None
    InboundGroupSession = None
    MegolmMessage = None
    PreKeyMessage = None
    Session = None
    VODOZEMAC_AVAILABLE = False
    logger.warning("vodozemac 未安装，E2EE 功能将不可用。请运行：pip install vodozemac")
