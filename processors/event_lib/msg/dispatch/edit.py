"""MSC4145 / MSC2676 message edit normalization."""

from collections import OrderedDict

from astrbot.api import logger

from .....constants import REL_TYPE_REPLACE


class MatrixEventProcessorMessagesEditMixin:
    """Normalize and validate m.replace edit events before delivery."""

    @staticmethod
    def _replacement_target_is_valid(event, target: object, target_event_id: str) -> bool:
        """Validate fields which clients can check for an m.replace target."""
        if not isinstance(target, dict):
            return True  # Network lookup unavailable: do not invent a rejection.

        target_id = target.get("event_id")
        if isinstance(target_id, str) and target_id and target_id != target_event_id:
            return False
        target_room_id = target.get("room_id")
        event_room_id = getattr(event, "room_id", None)
        if (
            isinstance(target_room_id, str)
            and target_room_id
            and isinstance(event_room_id, str)
            and event_room_id
            and target_room_id != event_room_id
        ):
            return False
        if target.get("sender") != getattr(event, "sender", None):
            return False
        if target.get("type") != getattr(event, "event_type", None):
            return False
        if "state_key" in target:
            return False

        target_content = target.get("content")
        target_relation = (
            target_content.get("m.relates_to")
            if isinstance(target_content, dict)
            else None
        )
        return not (
            isinstance(target_relation, dict)
            and target_relation.get("rel_type") == REL_TYPE_REPLACE
        )

    async def _fetch_replacement_target(self, event, target_event_id: str):
        """Fetch a replacement target for validity checks when possible."""
        get_event = getattr(getattr(self, "client", None), "get_event", None)
        if not target_event_id or not callable(get_event):
            return None
        try:
            return await get_event(getattr(event, "room_id", ""), target_event_id)
        except Exception as exc:
            logger.debug(f"校验 m.replace target 时获取原事件失败：{exc}")
            return None

    def _record_latest_replacement(self, event, original_event_id: str) -> bool:
        """Return False for a stale replacement revision.

        Matrix v1.16 clarifies that the newest valid replacement is selected by
        ``origin_server_ts`` and then, for equal timestamps, the
        lexicographically largest ``event_id``.
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

    async def _normalize_message_edit(self, event, event_content) -> bool:
        """Validate and normalize an edit event's content in place.

        Returns True when the edit must be skipped, False to continue with the
        normalized event content.
        """
        relates_to = event_content.get("m.relates_to", {})
        if not (
            isinstance(relates_to, dict)
            and relates_to.get("rel_type") == REL_TYPE_REPLACE
        ):
            return False

        original_event_id = relates_to.get("event_id")
        if not isinstance(original_event_id, str) or not original_event_id:
            logger.warning("忽略缺少 target event_id 的 m.replace 事件")
            return True

        # Stable replacement events require m.new_content.  Do not let a
        # malformed edit enter the ordering cache, otherwise a high timestamp
        # could suppress a later valid revision.
        new_content = event_content.get("m.new_content")
        if not isinstance(new_content, dict):
            logger.warning(
                f"忽略缺少 m.new_content 的 m.replace：{getattr(event, 'event_id', '')}"
            )
            return True

        target = await self._fetch_replacement_target(event, original_event_id)
        if target is not None and not self._replacement_target_is_valid(
            event, target, original_event_id
        ):
            logger.warning(
                "忽略无效 m.replace（room/sender/type/state/target 不匹配）："
                f"{getattr(event, 'event_id', '')} -> {original_event_id}"
            )
            return True
        if target is not None:
            # Reuse the validated target in the adapter callback to avoid a
            # second GET /event request solely for quote context.
            setattr(event, "_validated_replace_target", target)

        if not self._record_latest_replacement(event, original_event_id):
            return True

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
        return False
