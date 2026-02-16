from pathlib import Path

from astrbot.api import logger

from ..storage_backend import StorageBackendConfig
from .storage import build_e2ee_data_store


class DeviceStore:
    _RECORD_TRUSTED_DEVICES = "trusted_devices"

    def __init__(
        self,
        data_path: Path,
        *,
        storage_backend_config: StorageBackendConfig,
        namespace_key: str | None = None,
    ):
        self.file_path = data_path / "trusted_devices.json"
        self.storage_backend_config = storage_backend_config
        self._data_store = build_e2ee_data_store(
            folder_path=data_path,
            namespace_key=namespace_key or data_path.as_posix(),
            storage_backend_config=self.storage_backend_config,
            json_filename_resolver=self._json_filename_resolver,
            store_name="trusted_devices",
        )
        self._devices = self._load()

    @staticmethod
    def _json_filename_resolver(_: str) -> str:
        return "trusted_devices.json"

    def _load(self) -> dict[str, str]:
        try:
            data = self._data_store.get(self._RECORD_TRUSTED_DEVICES)
            if isinstance(data, dict):
                return data
        except Exception as e:
            logger.error(f"Failed to load trusted devices: {e}")
        return {}

    def _save(self):
        try:
            self._data_store.upsert(self._RECORD_TRUSTED_DEVICES, self._devices)
        except Exception as e:
            logger.error(f"Failed to save trusted devices: {e}")

    def add_device(self, user_id: str, device_id: str, fingerprint: str):
        key = f"{user_id}|{device_id}"
        self._devices[key] = fingerprint
        self._save()

    def get_fingerprint(self, user_id: str, device_id: str) -> str | None:
        key = f"{user_id}|{device_id}"
        return self._devices.get(key)

    def is_trusted(self, user_id: str, device_id: str, fingerprint: str) -> bool:
        stored_fingerprint = self.get_fingerprint(user_id, device_id)
        return stored_fingerprint == fingerprint
