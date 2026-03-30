from __future__ import annotations

import copy
import time
from pathlib import Path
from typing import Any

from astrbot.api import logger

from .storage_backend import MatrixFolderDataStore, build_folder_namespace


class MatrixOutboundTracker:
    """Persist outbound room sends so failed sends can be diagnosed/resubmitted."""

    _TERMINAL_STATES = {"sent", "failed"}

    def __init__(
        self,
        *,
        user_storage_dir: Path,
        store_path: str | Path,
        backend: str,
        pgsql_dsn: str = "",
        pgsql_schema: str = "public",
        pgsql_table_prefix: str = "matrix_store",
    ) -> None:
        self.user_storage_dir = Path(user_storage_dir)
        self.folder_path = self.user_storage_dir / "outbound"
        namespace = build_folder_namespace(self.folder_path, Path(store_path))
        self.store = MatrixFolderDataStore(
            folder_path=self.folder_path,
            namespace_key=namespace,
            backend=backend,
            sqlite_db_filename="outbound.db",
            pgsql_dsn=pgsql_dsn,
            pgsql_schema=pgsql_schema,
            pgsql_table_prefix=pgsql_table_prefix,
        )
        self._recent_keys_key = "__recent_keys__"
        self._record_limit = 200

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def _remember_key(self, txn_id: str) -> None:
        keys = self.store.get(self._recent_keys_key) or []
        if txn_id in keys:
            keys = [k for k in keys if k != txn_id]
        keys.append(txn_id)
        if len(keys) > self._record_limit:
            keys = keys[-self._record_limit :]
        self.store.upsert(self._recent_keys_key, keys)

    def _load_keys(self) -> list[str]:
        keys = self.store.get(self._recent_keys_key) or []
        if not isinstance(keys, list):
            return []
        return [str(key) for key in keys if str(key or "").strip()]

    def record_attempt(
        self,
        *,
        txn_id: str,
        action: str,
        room_id: str,
        event_type: str,
        content: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        existing = self.store.get(txn_id) or {}
        attempts = int(existing.get("attempts") or 0) + 1
        created_at = int(existing.get("created_at") or self._now_ms())
        record = {
            "txn_id": txn_id,
            "action": action,
            "room_id": room_id,
            "event_type": event_type,
            "content": copy.deepcopy(content) if isinstance(content, dict) else {},
            "state": "pending",
            "attempts": attempts,
            "created_at": created_at,
            "updated_at": self._now_ms(),
            "last_error": None,
            "event_id": existing.get("event_id"),
            "metadata": metadata or existing.get("metadata") or {},
        }
        self.store.upsert(txn_id, record)
        self._remember_key(txn_id)

    def mark_success(self, txn_id: str, response: dict[str, Any] | None) -> None:
        record = self.store.get(txn_id) or {"txn_id": txn_id}
        record["state"] = "sent"
        record["updated_at"] = self._now_ms()
        record["last_error"] = None
        if isinstance(response, dict):
            record["event_id"] = response.get("event_id") or record.get("event_id")
        self.store.upsert(txn_id, record)
        self._remember_key(txn_id)

    def mark_failure(self, txn_id: str, error: Exception | str) -> None:
        record = self.store.get(txn_id) or {"txn_id": txn_id}
        record["state"] = "failed"
        record["updated_at"] = self._now_ms()
        record["last_error"] = str(error)
        self.store.upsert(txn_id, record)
        self._remember_key(txn_id)

    def list_records(
        self, *, states: set[str] | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for key in reversed(self._load_keys()):
            record = self.store.get(key)
            if not isinstance(record, dict):
                continue
            if states and record.get("state") not in states:
                continue
            results.append(record)
            if len(results) >= limit:
                break
        return results

    def summary(self) -> dict[str, Any]:
        counts = {"pending": 0, "failed": 0, "sent": 0}
        for key in self._load_keys():
            record = self.store.get(key)
            if not isinstance(record, dict):
                continue
            state = str(record.get("state") or "")
            if state in counts:
                counts[state] += 1
        return counts

    async def resend_pending(self, client, *, limit: int = 20) -> list[dict[str, Any]]:
        retried: list[dict[str, Any]] = []
        for record in self.list_records(states={"pending", "failed"}, limit=limit):
            txn_id = str(record.get("txn_id") or "").strip()
            action = str(record.get("action") or "send_message")
            room_id = str(record.get("room_id") or "")
            event_type = str(record.get("event_type") or "")
            content = (
                record.get("content") if isinstance(record.get("content"), dict) else {}
            )
            if not txn_id or not room_id or not event_type:
                continue
            try:
                if action == "send_room_event":
                    response = await client.send_room_event(
                        room_id=room_id,
                        event_type=event_type,
                        content=copy.deepcopy(content),
                        txn_id=txn_id,
                    )
                elif action == "redact_event":
                    target_event_id = str(
                        (record.get("metadata") or {}).get("event_id") or ""
                    )
                    if not target_event_id:
                        raise ValueError("missing redaction target event_id")
                    response = await client.redact_event(
                        room_id=room_id,
                        event_id=target_event_id,
                        reason=(record.get("metadata") or {}).get("reason"),
                        txn_id=txn_id,
                    )
                else:
                    response = await client.send_message(
                        room_id=room_id,
                        msg_type=event_type,
                        content=copy.deepcopy(content),
                        txn_id=txn_id,
                    )
                retried.append(
                    {
                        "txn_id": txn_id,
                        "ok": True,
                        "event_id": (response or {}).get("event_id"),
                    }
                )
            except Exception as e:
                logger.warning(f"重试待发送 Matrix 事件失败 {txn_id}: {e}")
                retried.append({"txn_id": txn_id, "ok": False, "error": str(e)})
        return retried
