"""
Crypto Store - E2EE 密钥和会话的持久化存储

使用可配置后端存储加密状态，包括：
- Olm 账户 (pickle 格式)
- Megolm 入站/出站会话
- 设备密钥
- 一次性密钥
"""

from pathlib import Path
from typing import Any

from astrbot.api import logger

from ..plugin_config import get_plugin_config
from .storage import build_e2ee_data_store


class CryptoStore:
    """E2EE 加密状态存储"""

    _RECORD_ACCOUNT = "olm_account"
    _RECORD_SESSIONS = "olm_sessions"
    _RECORD_MEGOLM_INBOUND = "megolm_inbound"
    _RECORD_MEGOLM_OUTBOUND = "megolm_outbound"
    _RECORD_DEVICE_KEYS = "device_keys"
    _RECORD_STORED_DEVICE_ID = "stored_device_id"
    _LEGACY_FILES = {
        _RECORD_ACCOUNT: "olm_account.json",
        _RECORD_SESSIONS: "olm_sessions.json",
        _RECORD_MEGOLM_INBOUND: "megolm_inbound.json",
        _RECORD_MEGOLM_OUTBOUND: "megolm_outbound.json",
        _RECORD_DEVICE_KEYS: "device_keys.json",
        _RECORD_STORED_DEVICE_ID: "stored_device_id.json",
    }

    def __init__(
        self,
        store_path: str | Path,
        user_id: str,
        device_id: str,
        *,
        namespace_key: str | None = None,
    ):
        """
        初始化加密存储

        Args:
            store_path: 存储目录路径
            user_id: 用户 ID (如 @bot:example.com)
            device_id: 设备 ID
        """
        self.store_path = Path(store_path)
        self.user_id = user_id
        self.device_id = device_id

        # 创建存储目录
        self.store_path.mkdir(parents=True, exist_ok=True)
        self._namespace_key = namespace_key or self.store_path.as_posix()
        self.storage_backend_config = get_plugin_config().storage_backend_config
        self._data_store = build_e2ee_data_store(
            folder_path=self.store_path,
            namespace_key=self._namespace_key,
            storage_backend_config=self.storage_backend_config,
            json_filename_resolver=self._json_filename_resolver,
            store_name="crypto",
        )

        # 内存缓存
        self._account_pickle: str | None = None
        self._olm_sessions: dict[str, list[str]] = {}  # sender_key -> [session_pickles]
        self._megolm_inbound: dict[str, str] = {}  # session_id -> pickle
        self._megolm_outbound: dict[str, str] = {}  # room_id -> pickle
        self._device_keys: dict[str, dict] = {}  # user_id -> {device_id: keys}

        # 检查 device_id 是否变化
        self._device_id_changed = self._check_device_id_change()

        # 加载现有数据
        self._load_all()

    @classmethod
    def _json_filename_resolver(cls, record_key: str) -> str:
        return cls._LEGACY_FILES.get(record_key, f"{record_key}.json")

    def _legacy_path_for_record(self, record_key: str) -> Path:
        return self.store_path / self._json_filename_resolver(record_key)

    def _read_record(self, record_key: str) -> Any | None:
        try:
            return self._data_store.get(record_key)
        except Exception as e:
            logger.error(f"读取加密存储记录失败 {record_key}: {e}")
            return None

    def _save_record(self, record_key: str, data: Any):
        try:
            self._data_store.upsert(record_key, data)
        except Exception as e:
            logger.error(f"保存加密存储记录失败 {record_key}: {e}")

    def _delete_record(self, record_key: str):
        try:
            self._data_store.delete(record_key)
            legacy_path = self._legacy_path_for_record(record_key)
            if legacy_path.exists():
                legacy_path.unlink()
        except Exception as e:
            logger.error(f"删除加密存储记录失败 {record_key}: {e}")

    def _check_device_id_change(self) -> bool:
        """
        检查 device_id 是否发生变化

        Returns:
            True 如果 device_id 变化了（需要清除旧数据）
        """
        stored = self._read_record(self._RECORD_STORED_DEVICE_ID)
        if not isinstance(stored, dict):
            # 第一次运行，保存当前 device_id
            self._save_device_id()
            return False

        try:
            stored_device_id = stored.get("device_id")

            if stored_device_id != self.device_id:
                logger.warning(
                    f"检测到 device_id 变化：{stored_device_id} -> {self.device_id}"
                )
                logger.warning("将清除旧的 Olm 账户和会话数据，创建新的密钥")
                # 清除旧数据
                self._clear_olm_data()
                # 保存新的 device_id
                self._save_device_id()
                return True

            return False
        except Exception as e:
            logger.warning(f"检查 device_id 变化失败：{e}")
            self._save_device_id()
            return False

    def _save_device_id(self):
        """保存当前 device_id 到文件"""
        self._save_record(
            self._RECORD_STORED_DEVICE_ID, {"device_id": self.device_id}
        )

    def _clear_olm_data(self):
        """清除 Olm 账户和会话数据（当 device_id 变化时）"""
        try:
            # 只清除 Olm 相关数据，保留 Megolm 会话（可以继续解密历史消息）
            self._delete_record(self._RECORD_ACCOUNT)
            self._account_pickle = None
            logger.info("已删除旧的 Olm 账户")

            self._delete_record(self._RECORD_SESSIONS)
            self._olm_sessions = {}
            logger.info("已删除旧的 Olm 会话")

            # 注意：不删除 Megolm 入站会话，因为它们仍然可以解密历史消息
            # 但需要删除出站会话，因为需要为新设备创建新的
            self._delete_record(self._RECORD_MEGOLM_OUTBOUND)
            self._megolm_outbound = {}
            logger.info("已删除旧的 Megolm 出站会话")

        except Exception as e:
            logger.error(f"清除旧数据失败：{e}")

    @property
    def device_id_changed(self) -> bool:
        """返回 device_id 是否发生了变化"""
        return self._device_id_changed

    def _load_all(self):
        """从磁盘加载所有存储数据"""
        try:
            account_data = self._read_record(self._RECORD_ACCOUNT)
            if isinstance(account_data, dict):
                pickle = account_data.get("pickle")
                if isinstance(pickle, str):
                    self._account_pickle = pickle
                logger.debug("加载了 Olm 账户")

            sessions_data = self._read_record(self._RECORD_SESSIONS)
            if isinstance(sessions_data, dict):
                self._olm_sessions = sessions_data
                logger.debug(f"加载了 {len(self._olm_sessions)} 个 Olm 会话")

            megolm_inbound_data = self._read_record(self._RECORD_MEGOLM_INBOUND)
            if isinstance(megolm_inbound_data, dict):
                self._megolm_inbound = megolm_inbound_data
                logger.debug(f"加载了 {len(self._megolm_inbound)} 个 Megolm 入站会话")

            megolm_outbound_data = self._read_record(self._RECORD_MEGOLM_OUTBOUND)
            if isinstance(megolm_outbound_data, dict):
                self._megolm_outbound = megolm_outbound_data
                logger.debug(f"加载了 {len(self._megolm_outbound)} 个 Megolm 出站会话")

            device_keys_data = self._read_record(self._RECORD_DEVICE_KEYS)
            if isinstance(device_keys_data, dict):
                self._device_keys = device_keys_data
                logger.debug(f"加载了 {len(self._device_keys)} 个用户的设备密钥")

        except Exception as e:
            logger.error(f"加载加密存储失败: {e}")

    # ========== Olm 账户 ==========

    def get_account_pickle(self) -> str | None:
        """获取 Olm 账户的 pickle"""
        return self._account_pickle

    def save_account_pickle(self, pickle: str):
        """保存 Olm 账户的 pickle"""
        self._account_pickle = pickle
        self._save_record(self._RECORD_ACCOUNT, {"pickle": pickle})

    def clear_account_pickle(self):
        """删除持久化的 Olm 账户 pickle。"""
        self._account_pickle = None
        self._delete_record(self._RECORD_ACCOUNT)

    # ========== Olm 会话 ==========

    def get_olm_sessions(self, sender_key: str) -> list[str]:
        """获取与特定发送者的 Olm 会话列表"""
        return self._olm_sessions.get(sender_key, [])

    def add_olm_session(self, sender_key: str, session_pickle: str):
        """添加 Olm 会话"""
        if sender_key not in self._olm_sessions:
            self._olm_sessions[sender_key] = []
        self._olm_sessions[sender_key].append(session_pickle)
        self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def update_olm_session(self, sender_key: str, index: int, session_pickle: str):
        """更新 Olm 会话"""
        if sender_key in self._olm_sessions and index < len(
            self._olm_sessions[sender_key]
        ):
            self._olm_sessions[sender_key][index] = session_pickle
            self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    def clear_olm_sessions(self, sender_key: str):
        """清除与特定发送者的所有 Olm 会话"""
        if sender_key in self._olm_sessions:
            del self._olm_sessions[sender_key]
            self._save_record(self._RECORD_SESSIONS, self._olm_sessions)

    # ========== Megolm 入站会话 ==========

    def get_megolm_inbound(self, session_id: str) -> str | None:
        """获取 Megolm 入站会话"""
        return self._megolm_inbound.get(session_id)

    def save_megolm_inbound(self, session_id: str, session_pickle: str):
        """保存 Megolm 入站会话"""
        self._megolm_inbound[session_id] = session_pickle
        self._save_record(self._RECORD_MEGOLM_INBOUND, self._megolm_inbound)

    def has_megolm_inbound(self, session_id: str) -> bool:
        """检查是否存在指定 Megolm 入站会话"""
        return session_id in self._megolm_inbound

    def get_megolm_inbound_count(self) -> int:
        """获取本地 Megolm 入站会话数量"""
        return len(self._megolm_inbound)

    # ========== Megolm 出站会话 ==========

    def get_megolm_outbound(self, room_id: str) -> str | None:
        """获取房间的 Megolm 出站会话"""
        return self._megolm_outbound.get(room_id)

    def save_megolm_outbound(self, room_id: str, session_pickle: str):
        """保存房间的 Megolm 出站会话"""
        self._megolm_outbound[room_id] = session_pickle
        self._save_record(self._RECORD_MEGOLM_OUTBOUND, self._megolm_outbound)

    def get_megolm_outbound_rooms(self) -> list[str]:
        """获取所有已持久化的 Megolm 出站会话房间 ID"""
        return list(self._megolm_outbound.keys())

    # ========== 设备密钥 ==========

    def get_device_keys(
        self, user_id: str, device_id: str | None = None
    ) -> dict[str, dict] | dict[str, str]:
        """获取用户的所有设备密钥"""
        user_keys = self._device_keys.get(user_id, {})
        if device_id is None:
            return user_keys

        raw_device_keys = user_keys.get(device_id, {})
        if not isinstance(raw_device_keys, dict):
            return {}

        keys_obj = raw_device_keys.get("keys", {})
        if not isinstance(keys_obj, dict):
            keys_obj = {}

        curve25519 = keys_obj.get(f"curve25519:{device_id}", "")
        ed25519 = keys_obj.get(f"ed25519:{device_id}", "")
        if not curve25519 and not ed25519:
            return {}

        return {
            "curve25519": curve25519,
            "ed25519": ed25519,
        }

    def save_device_keys(self, user_id: str, device_id: str, keys: dict):
        """保存设备密钥"""
        if user_id not in self._device_keys:
            self._device_keys[user_id] = {}
        self._device_keys[user_id][device_id] = keys
        self._save_record(self._RECORD_DEVICE_KEYS, self._device_keys)

    def get_all_device_keys(self) -> dict[str, dict]:
        """获取所有已知的设备密钥"""
        return self._device_keys
