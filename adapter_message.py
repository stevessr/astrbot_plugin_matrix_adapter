"""
Matrix adapter message helpers.
"""

import base64
import json
import time
from pathlib import Path

from astrbot.api import logger

from .plugin_config import get_plugin_config


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


class MatrixAdapterMessageMixin:
    async def _resolve_reaction_target_summary(self, room, event_id: str) -> str:
        if not event_id or not self.client:
            return ""
        try:
            event = await self.client.get_event(room.room_id, event_id)
        except Exception as e:
            logger.debug(f"获取 reaction 目标事件失败：{e}")
            event = None

        if event:
            sender_id = event.get("sender", "") or ""
            sender_name = room.members.get(sender_id, sender_id) if sender_id else ""
            event_type = event.get("type") or event.get("event_type") or ""
            content = event.get("content") or {}

            body = ""
            if event_type == "m.room.message":
                msgtype = content.get("msgtype") or ""
                body = content.get("body") or ""
                if not body and msgtype in ("m.image", "m.video", "m.audio", "m.file"):
                    body = msgtype
                if msgtype == "m.sticker" and not body:
                    body = "sticker"
            elif event_type == "m.reaction":
                reaction = content.get("m.relates_to", {}).get("key", "")
                body = f"[reaction] {reaction}".strip()
            elif event_type == "m.room.encrypted":
                body = "[encrypted]"
            elif event_type == "m.room.redaction":
                body = "[redaction]"
            else:
                body = (
                    content.get("body")
                    or content.get("name")
                    or content.get("topic")
                    or ""
                )

            body = _normalize_text(body)
            if sender_name and sender_id:
                sender = f"{sender_name}/{sender_id}"
            else:
                sender = sender_name or sender_id

            if sender and body:
                return f"{sender}: {body}"
            if sender:
                return sender
            if body:
                return body
            if event_type:
                return event_type

        return _find_stalk_archive_message(room.room_id, event_id)

    async def message_callback(self, room, event):
        """
        Process a message event (called by event processor after filtering)

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            sender_id = getattr(event, "sender", "") or ""
            sender_name = room.members.get(sender_id, sender_id) if sender_id else ""

            if getattr(event, "msgtype", None) == "m.reaction":
                # Reactions should not enter the normal pipeline to avoid LLM replies.
                try:
                    relates_to = event.content.get("m.relates_to", {})
                    emoji = relates_to.get("key") or event.body or ""
                    target = relates_to.get("event_id", "")
                    target_summary = ""
                    if target:
                        target_summary = await self._resolve_reaction_target_summary(
                            room, target
                        )
                    if emoji and target:
                        text = f"[reaction] {emoji} -> {target}"
                    elif emoji:
                        text = f"[reaction] {emoji}"
                    elif target:
                        text = f"[reaction] -> {target}"
                    else:
                        text = "[reaction]"
                    if target_summary:
                        text = f"{text} ({target_summary})"
                    # Reaction 日志改为 debug，以减少高频 info 输出
                    logger.debug(f"[matrix(matrix)] {sender_name}/{sender_id}: {text}")
                except Exception:
                    pass
                return  # Reactions 已处理，不再进入后续消息/系统事件转换流程

            # 预回应表情：检查是否为 @机器人或唤醒命令
            if getattr(event, "msgtype", None):
                abm = await self.receiver.convert_message(room, event)
            else:
                abm = await self.receiver.convert_system_event(room, event)
            if abm is None:
                logger.warning(f"转换消息失败：{event}")
                return

            if abm and get_plugin_config().force_message_type == "stalk":
                record = {
                    "ts": int(time.time() * 1000),
                    "room_id": abm.session_id,
                    "event_id": getattr(event, "event_id", ""),
                    "sender_id": sender_id,
                    "sender_name": sender_name,
                    "message_str": abm.message_str,
                    "message": abm.message,
                    "raw_message": abm.raw_message,
                }
                _append_stalk_archive(abm.session_id, record)

            if get_plugin_config().force_message_type != "stalk":
                await self.handle_msg(abm, event_id=getattr(event, "event_id", None))
        except Exception as e:
            logger.error(f"消息回调时出错：{e}")

    async def handle_msg(self, message, event_id: str | None = None):
        try:
            from .matrix_event import MatrixPlatformEvent

            message_event = MatrixPlatformEvent(
                message_str=message.message_str,
                message_obj=message,
                platform_meta=self.meta(),
                session_id=message.session_id,
                client=self.client,
                enable_threading=self._matrix_config.enable_threading,
                e2ee_manager=self.e2ee_manager,
                use_notice=self._matrix_config.use_notice,
            )

            # 预回应表情：检查是否需要触发
            # 条件：1. 配置启用 2. 表情列表非空 3. 消息包含 @机器人或唤醒前缀
            try:
                # 从插件配置中读取预回应表情设置（仅记录必要信息）
                plugin_cfg = get_plugin_config()
                pre_ack_enable = plugin_cfg.pre_ack_emoji_enable
                pre_ack_emojis = plugin_cfg.pre_ack_emoji_emojis

                logger.debug(f"[pre_ack] 配置检查：enable={pre_ack_enable}, event_id={event_id}")
                if pre_ack_enable and pre_ack_emojis and event_id:
                    import random

                    from astrbot.api.message_components import At

                    should_react = False
                    react_reason = None

                    # 检查消息链中是否有 @机器人（只记录触发结果，避免打印整个消息内容）
                    for segment in getattr(message, "message", []):
                        if isinstance(segment, At):
                            at_target = getattr(segment, "qq", None) or getattr(
                                segment, "user_id", None
                            )
                            if at_target and str(at_target) == str(
                                self._matrix_config.user_id
                            ):
                                should_react = True
                                react_reason = "mention"
                                break

                    # 检查是否以唤醒前缀开头
                    if not should_react:
                        from astrbot.core import astrbot_config

                        wake_prefixes = astrbot_config.get("wake_prefix", ["/"])
                        message_str = (getattr(message, "message_str", "") or "").strip()
                        for wake_prefix in wake_prefixes:
                            if message_str.startswith(wake_prefix):
                                should_react = True
                                react_reason = f"wake_prefix:{wake_prefix}"
                                break

                    # 若触发则发送反应并记录触发原因（不打印过多上下文）
                    if should_react:
                        emoji = random.choice(pre_ack_emojis)
                        if not hasattr(message, "message_id"):
                            message.message_id = event_id
                        await message_event.react(emoji)
                        logger.debug(f"[pre_ack] 发送预回应表情：{emoji}, reason={react_reason}")
            except Exception as e:
                logger.debug(f"预回应表情发送失败：{e}")

            self.commit_event(message_event)
            # 仅记录必要的事件元信息，避免在 debug 中打印过多用户标识
            logger.debug(
                f"Message event committed: session={getattr(message, 'session_id', 'N/A')}, type={getattr(message, 'type', 'N/A')}"
            )
        except Exception as e:
            logger.error(f"处理消息失败：{e}")
