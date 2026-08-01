"""
Persist mixin for CryptoStore — handles async persistence, device ID tracking, and data loading.
"""

import copy
from concurrent.futures import Future, wait
from pathlib import Path
from typing import Any

from astrbot.api import logger


class CryptoStorePersistMixin:
    """Persistence layer for E2EE crypto store."""

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

    @classmethod
    def _json_filename_resolver(cls, record_key: str) -> str:
        return cls._LEGACY_FILES.get(record_key, f"{record_key}.json")

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

    def _on_persist_future_done(
        self,
        future: Future,
        *,
        operation: str,
        record_key: str,
    ) -> None:
        try:
            future.result()
        except Exception as e:
            logger.error(f"{operation} 加密存储记录失败 {record_key}: {e}")
        finally:
            with self._persist_futures_lock:
                self._persist_futures.discard(future)
            self._persist_slots.release()

    def _submit_persist_job(
        self,
        operation: str,
        record_key: str,
        job,
        *job_args,
    ) -> None:
        if self._initializing or self._closed:
            job(*job_args)
            return

        acquired = self._persist_slots.acquire(
            timeout=self._PERSIST_QUEUE_WAIT_TIMEOUT_SECONDS
        )
        if not acquired:
            logger.warning(
                "E2EE storage queue is saturated; falling back to synchronous write "
                f"(op={operation}, key={record_key})"
            )
            job(*job_args)
            return

        try:
            future = self._persist_executor.submit(job, *job_args)
            with self._persist_futures_lock:
                self._persist_futures.add(future)
            future.add_done_callback(
                lambda done: self._on_persist_future_done(
                    done, operation=operation, record_key=record_key
                )
            )
        except Exception as e:
            self._persist_slots.release()
            logger.warning(
                f"提交加密存储任务失败 {operation}/{record_key}，回退同步写入：{e}"
            )
            job(*job_args)

    def flush(self, timeout: float | None = None) -> bool:
        if timeout is None:
            timeout = self._PERSIST_FLUSH_TIMEOUT_SECONDS
        with self._persist_futures_lock:
            pending_futures = list(self._persist_futures)
        if not pending_futures:
            return True
        _, not_done = wait(pending_futures, timeout=timeout)
        if not_done:
            logger.warning(
                f"E2EE storage flush timed out with {len(not_done)} pending jobs"
            )
            return False
        return True

    def close(self, timeout: float | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        flushed = self.flush(timeout=timeout)
        if flushed:
            self._persist_executor.shutdown(wait=True, cancel_futures=False)
        else:
            self._persist_executor.shutdown(wait=False, cancel_futures=True)

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
                    "检测到 device_id 变化："
                    f"{self._redact_device_id(stored_device_id)} -> "
                    f"{self._redact_device_id(self.device_id)}"
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
        self._save_record(self._RECORD_STORED_DEVICE_ID, {"device_id": self.device_id})

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
            self._delete_record(self._RECORD_MEGOLM_OUTBOUND_META)
            self._megolm_outbound_meta = {}
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

            megolm_inbound_meta = self._read_record(self._RECORD_MEGOLM_INBOUND_META)
            if isinstance(megolm_inbound_meta, dict):
                self._megolm_inbound_meta = megolm_inbound_meta

            megolm_replay = self._read_record(self._RECORD_MEGOLM_REPLAY)
            if isinstance(megolm_replay, dict):
                self._megolm_replay = megolm_replay

            megolm_outbound_data = self._read_record(self._RECORD_MEGOLM_OUTBOUND)
            if isinstance(megolm_outbound_data, dict):
                self._megolm_outbound = megolm_outbound_data
                logger.debug(f"加载了 {len(self._megolm_outbound)} 个 Megolm 出站会话")

            megolm_outbound_meta = self._read_record(self._RECORD_MEGOLM_OUTBOUND_META)
            if isinstance(megolm_outbound_meta, dict):
                self._megolm_outbound_meta = megolm_outbound_meta

            device_keys_data = self._read_record(self._RECORD_DEVICE_KEYS)
            if isinstance(device_keys_data, dict):
                self._device_keys = device_keys_data
                logger.debug(f"加载了 {len(self._device_keys)} 个用户的设备密钥")

        except Exception as e:
            logger.error(f"加载加密存储失败：{e}")
