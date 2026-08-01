"""Core construction and shared state for the crypto store."""

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ...plugin_config import get_plugin_config
from ..storage import build_e2ee_data_store


class CryptoStoreCoreMixin:
    """E2EE 加密状态存储"""

    _RECORD_ACCOUNT = "olm_account"
    _RECORD_SESSIONS = "olm_sessions"
    _RECORD_MEGOLM_INBOUND = "megolm_inbound"
    _RECORD_MEGOLM_INBOUND_META = "megolm_inbound_meta"
    _RECORD_MEGOLM_REPLAY = "megolm_replay"
    _RECORD_MEGOLM_OUTBOUND = "megolm_outbound"
    _RECORD_MEGOLM_OUTBOUND_META = "megolm_outbound_meta"
    _RECORD_DEVICE_KEYS = "device_keys"
    _RECORD_STORED_DEVICE_ID = "stored_device_id"
    _PERSIST_QUEUE_WAIT_TIMEOUT_SECONDS = 15.0
    _PERSIST_FLUSH_TIMEOUT_SECONDS = 10.0
    _LEGACY_FILES = {
        _RECORD_ACCOUNT: "olm_account.json",
        _RECORD_SESSIONS: "olm_sessions.json",
        _RECORD_MEGOLM_INBOUND: "megolm_inbound.json",
        _RECORD_MEGOLM_INBOUND_META: "megolm_inbound_meta.json",
        _RECORD_MEGOLM_REPLAY: "megolm_replay.json",
        _RECORD_MEGOLM_OUTBOUND: "megolm_outbound.json",
        _RECORD_MEGOLM_OUTBOUND_META: "megolm_outbound_meta.json",
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
        self._persist_executor = ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="matrix-e2ee-store",
        )
        try:
            configured_pending_writes = int(
                get_plugin_config().e2ee_store_max_pending_writes
            )
        except Exception:
            configured_pending_writes = 256
        self._max_pending_writes = max(1, min(configured_pending_writes, 8192))
        self._persist_slots = threading.BoundedSemaphore(self._max_pending_writes)
        self._persist_futures: set[Future] = set()
        self._persist_futures_lock = threading.Lock()
        self._closed = False
        self._initializing = True

        # 内存缓存
        self._account_pickle: str | None = None
        self._olm_sessions: dict[str, list[str]] = {}  # sender_key -> [session_pickles]
        self._megolm_inbound: dict[str, str] = {}  # session_id -> pickle
        self._megolm_inbound_meta: dict[str, dict[str, Any]] = {}
        self._megolm_replay: dict[str, dict[str, str]] = {}
        self._megolm_replay_lock = threading.Lock()
        self._megolm_outbound: dict[str, str] = {}  # room_id -> pickle
        self._megolm_outbound_meta: dict[str, dict[str, Any]] = {}
        self._device_keys: dict[str, dict] = {}  # user_id -> {device_id: keys}

        # 检查 device_id 是否变化
        self._device_id_changed = self._check_device_id_change()

        # 加载现有数据
        self._load_all()
        self._initializing = False
