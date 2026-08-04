"""Cross-signing constructor and local persistence setup."""

from collections.abc import Awaitable, Callable
from pathlib import Path

from .....config.plugin import get_plugin_config as _DEFAULT_GET_PLUGIN_CONFIG
from ....storage import build_e2ee_data_store as _DEFAULT_BUILD_E2EE_DATA_STORE
from ..compat import resolve_core_symbol


class CrossSigningCoreSetupMixin:
    """Assemble cross-signing state and prepare local persistence."""

    def __init__(
        self,
        client,
        user_id: str,
        device_id: str,
        olm_machine,
        password: str | None = None,
        *,
        secret_storage=None,
        request_secret_from_devices: Callable[[str], Awaitable[str | None]]
        | None = None,
        repair_current_device_keys: Callable[[], Awaitable[None]] | None = None,
        namespace_key: str | None = None,
    ):
        self.client = client
        self.user_id = (
            user_id
            if isinstance(user_id, str) and user_id.startswith("@")
            else f"@{user_id}"
        )
        self.device_id = device_id
        self.olm = olm_machine
        self.password = password
        self.secret_storage = secret_storage
        self.request_secret_from_devices = request_secret_from_devices
        self.repair_current_device_keys = repair_current_device_keys

        self._master_key: str | None = None
        self._self_signing_key: str | None = None
        self._user_signing_key: str | None = None

        # 私钥（Raw 32B），仅本地持久化
        self._master_priv = None
        self._self_signing_priv = None
        self._user_signing_priv = None
        self._pending_secret_requests: set[str] = set()

        get_config = resolve_core_symbol(
            "get_plugin_config", _DEFAULT_GET_PLUGIN_CONFIG
        )
        self.storage_backend_config = get_config().storage_backend_config

        # 本地持久化存储（与 E2EE store 同目录）
        try:
            path_cls = resolve_core_symbol("Path", Path)
            build_store = resolve_core_symbol(
                "build_e2ee_data_store", _DEFAULT_BUILD_E2EE_DATA_STORE
            )
            store_path = path_cls(self.olm.store.store_path)
            self._storage_store = build_store(
                folder_path=store_path,
                namespace_key=namespace_key or store_path.as_posix(),
                storage_backend_config=self.storage_backend_config,
                json_filename_resolver=self._json_filename_resolver,
                store_name="cross_signing",
            )
        except Exception:
            self._storage_store = None
