"""MSC4145 / MSC2676 message edit normalization."""

from astrbot.api import logger


class MatrixEventProcessorMessagesEditMixin:
    """Normalize m.replace edit events before delivery."""

    def _normalize_message_edit(self, event, event_content) -> bool:
        """Normalize an edit event's content in place.

        Returns True when the edit must be skipped (the original message was
        already processed), False to continue with the (possibly normalized)
        event content.
        """
        # MSC4145 / MSC2676: 处理 m.replace 编辑事件
        # 编辑复用原始事件 ID 检测：如果原始消息已被处理，跳过编辑事件
        # 避免 LLM 对同一个消息的编辑版本重复响应。
        # 若原始消息尚未处理，则用 m.new_content 替换事件内容，
        # 让 LLM 看到的是修正后的文本而非 "* 旧文本" 回退。
        relates_to = event_content.get("m.relates_to", {})
        if not (
            isinstance(relates_to, dict) and relates_to.get("rel_type") == "m.replace"
        ):
            return False

        original_event_id = relates_to.get("event_id")
        if original_event_id and self._is_message_processed(original_event_id):
            logger.debug(
                f"忽略已处理消息的编辑：{original_event_id} -> {event.event_id}"
            )
            return True

        # 原始消息未处理：使用 m.new_content 替换事件内容
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
