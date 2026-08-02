import copy
from pathlib import Path
from typing import Any

from astrbot.api import logger


class CryptoStorePersistRecordsMixin:
    def _legacy_path_for_record(self, record_key: str) -> Path:
        return self.store_path / self._json_filename_resolver(record_key)

    @staticmethod
    def _clone_record_data(data: Any) -> Any:
        try:
            return copy.deepcopy(data)
        except Exception:
            return data

    @staticmethod
    def _redact_device_id(device_id: str | None) -> str:
        if not isinstance(device_id, str) or not device_id:
            return "<empty>"
        normalized = device_id.strip()
        if len(normalized) <= 4:
            return "***"
        return f"{normalized[:2]}***{normalized[-2:]}"

    def _read_record(self, record_key: str) -> Any | None:
        try:
            return self._data_store.get(record_key)
        except Exception as e:
            logger.error(f"读取加密存储记录失败 {record_key}: {e}")
            return None

    def _save_record(self, record_key: str, data: Any):
        try:
            payload = self._clone_record_data(data)
            self._submit_persist_job(
                "保存",
                record_key,
                self._data_store.upsert,
                record_key,
                payload,
            )
        except Exception as e:
            logger.error(f"保存加密存储记录失败 {record_key}: {e}")

    def _delete_record_sync(self, record_key: str) -> None:
        self._data_store.delete(record_key)
        legacy_path = self._legacy_path_for_record(record_key)
        if legacy_path.exists():
            legacy_path.unlink()

    def _delete_record(self, record_key: str):
        try:
            self._submit_persist_job(
                "删除",
                record_key,
                self._delete_record_sync,
                record_key,
            )
        except Exception as e:
            logger.error(f"删除加密存储记录失败 {record_key}: {e}")
