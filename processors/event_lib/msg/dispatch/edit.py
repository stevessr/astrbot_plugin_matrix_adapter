"""MSC4145 / MSC2676 message edit normalization."""

from astrbot.api import logger

from .....constants import REL_TYPE_REPLACE


class MatrixEventProcessorMessagesEditMixin:
    """Normalize m.replace edit events before delivery."""

    def _normalize_message_edit(self, event, event_content) -> bool:
        """Normalize an edit event's content in place.

        Returns True when the edit must be skipped, False to continue with the
        (possibly normalized) event content.  Edits are delivered even when
        their target message was already processed; the callback adds the
        target text as quote context.
        """
        # MSC4145 / MSC2676: 处理 m.replace 编辑事件。
        # 编辑事件始终继续进入回调，由回调补充原消息 quote，避免丢失
        # 编辑前后的上下文。
        relates_to = event_content.get("m.relates_to", {})
        if not (
            isinstance(relates_to, dict)
            and relates_to.get("rel_type") == REL_TYPE_REPLACE
        ):
            return False

        original_event_id = relates_to.get("event_id")
        # Normalize the replacement payload, but always deliver the edit.  The
        # callback fetches the target event and adds ``[quote] ->`` context.
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
            if "format" in new_content:
                event_content["format"] = new_content["format"]
            if "msgtype" in new_content:
                event_content["msgtype"] = new_content["msgtype"]
            event.body = cleaned_body
            event.msgtype = event_content.get("msgtype", event.msgtype)
            logger.debug(
                f"编辑事件已规范化：{event.event_id} (原始={original_event_id})"
            )
        else:
            # 没有 m.new_content 时至少去掉 * 前缀
            body = event_content.get("body", "")
            if body.startswith("* "):
                cleaned = body[2:]
                event_content["body"] = cleaned
                event.body = cleaned
                logger.debug(
                    f"编辑回退内容已清理（无 m.new_content）：{event.event_id}"
                )

        return False
