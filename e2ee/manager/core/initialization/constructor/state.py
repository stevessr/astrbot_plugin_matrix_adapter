"""Runtime state fields for the E2EE manager."""

import asyncio

from .....constants import (
    DEFAULT_OLM_RECOVERY_RETRY_SEC,
    DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC,
    DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC,
    DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC,
)
from .....olm import OlmMachine
from .....store import CryptoStore


class E2EEManagerCoreInitializationConstructorStateMixin:
    def _init_runtime_state(self) -> None:
        self._store: CryptoStore | None = None
        self._olm: OlmMachine | None = None
        self._verification = None  # SASVerification
        self._key_backup = None  # KeyBackup
        self._cross_signing = None  # CrossSigning
        self._initialized = False
        self._closing = False
        # session_id -> {"@user:server|DEVICEID", ...}
        self._room_key_share_cache: dict[str, set[str]] = {}
        # A single distribution pass per Megolm session prevents duplicate
        # /keys/claim and to-device sends from periodic and event-driven paths.
        self._room_key_share_locks: dict[str, asyncio.Lock] = {}
        # room_id -> (members, monotonic timestamp)
        self._room_members_cache: dict[str, tuple[list[str], float]] = {}
        self._room_members_cache_ttl_sec = DEFAULT_ROOM_MEMBER_CACHE_TTL_SEC
        self._room_history_visibility: dict[str, str] = {}
        self._room_encryption_config: dict[str, dict] = {}
        # throttle one-time key maintenance to avoid frequent uploads
        self._last_otk_maintenance_ts = 0.0
        # 定期密钥分发检查的任务和锁
        self._key_share_check_task: asyncio.Task | None = None
        self._key_share_check_lock = asyncio.Lock()
        # Missing-session requests reuse their Matrix request ID and are throttled.
        self._pending_room_key_requests: dict[tuple[str, str], dict] = {}
        self._room_key_request_lock = asyncio.Lock()
        self._room_key_request_retry_interval_sec = DEFAULT_ROOM_KEY_REQUEST_RETRY_SEC
        self._room_key_request_expiry_sec = DEFAULT_ROOM_KEY_REQUEST_EXPIRY_SEC
        # m.no_olm MUST be emitted only once per failed peer until an Olm send
        # succeeds. Incoming recovery attempts are independently rate-limited.
        self._no_olm_withheld_sent: set[tuple[str, str]] = set()
        self._olm_recovery_attempts: dict[tuple[str, str], float] = {}
        self._olm_recovery_retry_interval_sec = DEFAULT_OLM_RECOVERY_RETRY_SEC
        self._room_key_withheld: dict[tuple[str, str, str], dict] = {}
