"""Retry operations for pending outbound events."""

import copy
from typing import Any

from astrbot.api import logger


class MatrixOutboundResendMixin:
    """Resend pending and failed outbound events through a client."""

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
