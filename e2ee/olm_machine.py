"""
Olm Machine - Olm/Megolm 加密操作封装

使用 vodozemac 实现加密/解密操作。
注意：此模块需要安装 vodozemac 库。
"""

from .crypto_store import CryptoStore
from .olm_machine_account import OlmMachineAccountMixin
from .olm_machine_keys import OlmMachineKeysMixin
from .olm_machine_megolm import OlmMachineMegolmMixin
from .olm_machine_olm import OlmMachineOlmMixin
from .olm_machine_types import (
    VODOZEMAC_AVAILABLE,
    Account,
    GroupSession,
    InboundGroupSession,
    Session,
)


class OlmMachine(
    OlmMachineAccountMixin,
    OlmMachineKeysMixin,
    OlmMachineOlmMixin,
    OlmMachineMegolmMixin,
):
    """
    Olm/Megolm 加密操作封装

    提供：
    - 设备密钥生成
    - Olm 会话管理
    - Megolm 加密/解密
    """

    def __init__(self, store: CryptoStore, user_id: str, device_id: str):
        """
        初始化 OlmMachine

        Args:
            store: 加密存储
            user_id: 用户 ID
            device_id: 设备 ID
        """
        if not VODOZEMAC_AVAILABLE:
            raise RuntimeError("vodozemac 未安装，无法使用 E2EE")

        self.store = store
        self.user_id = user_id
        self.device_id = device_id

        # 生成 pickle key (用于加密存储的 Olm 状态)
        # 基于 user_id 和 device_id 生成稳定的密钥
        import hashlib

        key_material = f"{user_id}:{device_id}:astrbot_e2ee".encode()
        self._pickle_key = hashlib.sha256(key_material).digest()

        # Olm 账户
        self._account: Account | None = None

        # Olm 会话缓存：sender_key -> [Session]
        self._olm_sessions: dict[str, list[Session]] = {}

        # Megolm 会话缓存
        self._megolm_inbound: dict[str, InboundGroupSession] = {}
        self._megolm_outbound: dict[str, GroupSession] = {}

        # 标记账户是否是新创建的（用于判断是否需要上传设备密钥）
        self._is_new_account = False

        # 初始化或加载账户
        self._init_account()

    @property
    def is_new_account(self) -> bool:
        """返回账户是否是新创建的"""
        return self._is_new_account
