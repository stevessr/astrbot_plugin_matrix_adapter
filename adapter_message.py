"""
Matrix adapter message helpers.
"""

import base64
import json
import time
from pathlib import Path

from astrbot.api import logger  # 转换消息链为可序列化格式
from astrbot.api.message_components import (
    At,
    AtAll,
    Image,
    Plain,
    Reply,
)

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


def _build_message_content(abm) -> dict:
    content = {
        "message": [],
        "raw_message": abm.message_str,
    }

    for component in abm.message:
        if isinstance(component, Plain):
            content["message"].append({"type": "plain", "text": component.text})
        elif isinstance(component, Image):
            content["message"].append(
                {
                    "type": "image",
                    "path": getattr(component, "path", ""),
                }
            )
        elif isinstance(component, At):
            content["message"].append(
                {
                    "type": "at",
                    "qq": component.qq,
                    "name": component.name,
                }
            )
        elif isinstance(component, AtAll):
            content["message"].append({"type": "at_all"})
        elif isinstance(component, Reply):
            content["message"].append(
                {
                    "type": "reply",
                    "id": component.id,
                    "message_str": component.message_str,
                    "sender_id": component.sender_id,
                    "sender_nickname": component.sender_nickname,
                }
            )
        else:
            content["message"].append(
                {
                    "type": getattr(component, "type", "unknown"),
                    "data": getattr(component, "data", {}),
                }
            )

    return content


class MatrixAdapterMessageMixin:
    async def message_callback(self, room, event):
        """
        Process a message event (called by event processor after filtering)

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            if getattr(event, "msgtype", None) == "m.reaction":
                # Reactions should not enter the normal pipeline to avoid LLM replies.
                try:
                    sender_id = getattr(event, "sender", "") or ""
                    sender_name = (
                        room.members.get(sender_id, sender_id) if sender_id else ""
                    )
                    relates_to = event.content.get("m.relates_to", {})
                    emoji = relates_to.get("key") or event.body or ""
                    target = relates_to.get("event_id", "")
                    if emoji and target:
                        text = f"[reaction] {emoji} -> {target}"
                    elif emoji:
                        text = f"[reaction] {emoji}"
                    elif target:
                        text = f"[reaction] -> {target}"
                    else:
                        text = "[reaction]"
                    logger.info(
                        f"[matrix(matrix)] {sender_name}/{sender_id}: {text}"
                    )
                except Exception:
                    pass
            if getattr(event, "msgtype", None):
                abm = await self.receiver.convert_message(room, event)
            else:
                abm = await self.receiver.convert_system_event(room, event)
            if abm is None:
                logger.warning(f"转换消息失败：{event}")
                return

            # 保存消息历史到 PlatformMessageHistory
            # 延迟获取 message_history_manager 以避免初始化顺序问题
            if not self.message_history_manager:
                try:
                    # 通过全局 Context 获取 message_history_manager
                    from astrbot.core.star.context import context as global_context

                    if global_context and hasattr(
                        global_context, "message_history_manager"
                    ):
                        self.message_history_manager = (
                            global_context.message_history_manager
                        )
                        logger.debug("已从 Context 获取 message_history_manager")
                except Exception as e:
                    logger.debug(f"获取 message_history_manager 失败：{e}")

            content = None
            sender_id = ""
            sender_name = ""
            if abm:
                sender_id = (
                    abm.sender.user_id if hasattr(abm, "sender") and abm.sender else ""
                )
                sender_name = (
                    abm.sender.nickname if hasattr(abm, "sender") and abm.sender else ""
                )

            if abm:
                content = _build_message_content(abm)

            if self.message_history_manager and abm:
                try:
                    # 保存到数据库
                    await self.message_history_manager.insert(
                        platform_id=self.meta().id or "matrix",
                        user_id=abm.session_id,
                        content=content,
                        sender_id=sender_id,
                        sender_name=sender_name,
                    )
                    logger.debug(
                        f"已保存消息历史：session_id={abm.session_id}, sender={sender_name}"
                    )
                except Exception as e:
                    logger.warning(f"保存消息历史失败：{e}")

            if abm and get_plugin_config().force_message_type == "stalk":
                record = {
                    "ts": int(time.time() * 1000),
                    "room_id": abm.session_id,
                    "event_id": getattr(event, "event_id", ""),
                    "sender_id": sender_id,
                    "sender_name": sender_name,
                    "message_str": abm.message_str,
                    "message": content["message"],
                    "raw_message": content["raw_message"],
                }
                _append_stalk_archive(abm.session_id, record)

            if get_plugin_config().force_message_type != "stalk":
                await self.handle_msg(abm)
        except Exception as e:
            logger.error(f"消息回调时出错：{e}")

    async def handle_msg(self, message):
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
            self.commit_event(message_event)
            logger.debug(
                f"Message event committed: session={getattr(message, 'session_id', 'N/A')}, type={getattr(message, 'type', 'N/A')}, sender={getattr(message.sender, 'user_id', 'N/A') if hasattr(message, 'sender') else 'N/A'}"
            )
        except Exception as e:
            logger.error(f"处理消息失败：{e}")
