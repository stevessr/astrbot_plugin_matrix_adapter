"""Stalk-mode message archive helpers."""

import base64
import json
from pathlib import Path

from astrbot.api import logger

from ...config.plugin import get_plugin_config
from ...constants import MSC4357_LIVE_MESSAGE_MARKER


def _stalk_archive_path(room_id: str) -> Path:
    encoded = (
        base64.urlsafe_b64encode(room_id.encode("utf-8")).decode("ascii").rstrip("=")
    )
    base_dir = get_plugin_config().store_path / "stalk_archive"
    return base_dir / f"{encoded}.jsonl"


def _append_stalk_archive(room_id: str, record: dict) -> None:
    try:
        archive_path = _stalk_archive_path(room_id)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        with archive_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    except Exception as e:
        logger.warning(f"写入 stalk 存档失败：{e}")


def _normalize_text(text: str, limit: int = 120) -> str:
    if not text:
        return ""
    cleaned = " ".join(str(text).split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 3)] + "..."


def _is_live_message_draft(event) -> bool:
    content = getattr(event, "content", {}) or {}
    return isinstance(content, dict) and (
        content.get(MSC4357_LIVE_MESSAGE_MARKER) is not None
    )


def _find_stalk_archive_message(room_id: str, event_id: str) -> str:
    if not event_id:
        return ""
    archive_path = _stalk_archive_path(room_id)
    if not archive_path.exists():
        return ""
    try:
        with archive_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("event_id") == event_id:
                    sender_name = record.get("sender_name") or record.get("sender_id")
                    message_str = _normalize_text(record.get("message_str", ""))
                    if sender_name and message_str:
                        return f"{sender_name}: {message_str}"
                    if sender_name:
                        return str(sender_name)
                    return message_str
    except Exception as e:
        logger.debug(f"读取 stalk 存档失败：{e}")
    return ""
