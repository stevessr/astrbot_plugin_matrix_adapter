"""MSC4145 / MSC2676 message edit normalization."""

from collections import OrderedDict

from astrbot.api import logger

from .....constants import REL_TYPE_REPLACE


class MatrixEventProcessorMessagesEditMixin:
    """Normalize m.replace edit events before delivery."""

    def _record_latest_replacement(self, event, original_event_id: str) -> bool:
        """Return False for a stale replacement revision.

        Matrix v1.16 clarifies that the newest valid replacement is selected by
        ``origin_server_ts`` and then, for equal timestamps, the
        lexicographically largest ``event_id``.  /sync and backfill may deliver
        revisions out of order, so remember the newest revision observed for a
        target and suppress older revisions.
        """
        if not original_event_id:
            return True

        cache = getattr(self, "_latest_replacements", None)
        if not isinstance(cache, OrderedDict):
            cache = OrderedDict()
            self._latest_replacements = cache

        room_id = str(getattr(event, "room_id", "") or "")
        event_id = str(getattr(event, "event_id", "") or "")
        raw_ts = getattr(event, "origin_server_ts", 0)
        try:
            origin_server_ts = int(raw_ts or 0)
        except (TypeError, ValueError):
            origin_server_ts = 0

        target_key = (room_id, original_event_id)
        revision_key = (origin_server_ts, event_id)
        previous = cache.get(target_key)
        if previous is not None and revision_key <= previous:
            logger.debug(
                "忽略旧 m.replace revision："
                f"target={original_event_id} revision={revision_key} latest={previous}"
            )
            return False

        cache[target_key] = revision_key
        cache.move_to_end(target_key, last=True)
        max_entries = int(getattr(self, "_max_processed_messages", 1000) or 1000)
        while len(cache) > max(1, max_entries):
            cache.popitem(last=False)
        return True

    def _normalize_message_edit(self, event, event_content) -> bool:
        """Normalize an edit event's content in place.

        Returns True when the edit must be skipped, False to continue with the
        (possibly normalized) event content.
        """
        relates_to = event_content.get("m.relates_to", {})
        if not (
            isinstance(relates_to, dict)
            and relates_to.get("rel_type") == REL_TYPE_REPLACE
        ):
            return False

        original_event_id = relates_to.get("event_id")
        original_event_id = (
            str(original_event_id) if isinstance(original_event_id, str) else ""
        )
        if not self._record_latest_replacement(event, original_event_id):
            return True

        # A replacement must include m.new_content.  Keep compatibility with
        # older clients which only sent a fallback body, but never let that
        # compatibility path affect ordering of newer valid edits.
        new_content = event_content.get("m.new_content")
        if isinstance(new_content, dict):
            old_body = event_content.get("body", "")
            cleaned_body = new_content.get("body", old_body)
            if cleaned_body and cleaned_body.startswith("* "):
                cleaned_body = cleaned_body[2:]
            event_content["body"] = cleaned_body
            if "formatted_body" in new_content:
                fb = new_content.get("formatted_body", "")
                if fb.startswith("* "):
                    fb = fb[2:]
                event_content["formatted_body"] = fb
            else:
                event_content.pop("formatted_body", None)
            if "format" in new_content:
                event_content["format"] = new_content["format"]
            else:
                event_content.pop("format", None)
            if "msgtype" in new_content:
                event_content["msgtype"] = new_content["msgtype"]
            event.body = cleaned_body
            event.msgtype = event_content.get("msgtype", event.msgtype)
            logger.debug(
                f"编辑事件已规范化：{event.event_id} (原始={original_event_id})"
            )
        else:
            body = event_content.get("body", "")
            if body.startswith("* "):
                cleaned = body[2:]
                event_content["body"] = cleaned
                event.body = cleaned
                logger.debug(
                    f"编辑回退内容已清理（无 m.new_content）：{event.event_id}"
                )

        return False
