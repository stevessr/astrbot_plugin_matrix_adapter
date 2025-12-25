import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class DeviceStore:
    def __init__(self, data_path: Path):
        self.file_path = data_path / "trusted_devices.json"
        self._devices = self._load()

    def _load(self) -> dict[str, str]:
        if not self.file_path.exists():
            return {}
        try:
            with open(self.file_path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load trusted devices: {e}")
            return {}

    def _save(self):
        try:
            with open(self.file_path, "w") as f:
                json.dump(self._devices, f, indent=4)
        except OSError as e:
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
