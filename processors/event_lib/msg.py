"""
Matrix Event Processor - Message Events Mixin
Handles processing of message events (decryption, edits, read receipts).
"""

from typing import TYPE_CHECKING

from astrbot.api import logger

from ...client.event_types import parse_event
from ...constants import (
    M_ROOM_ENCRYPTED,
    M_ROOM_MESSAGE,
    TIMESTAMP_BUFFER_MS_1000,
)
if TYPE_CHECKING:
    from ...e2ee import E2EEManager


class MatrixEventProcessorMessagesMixin:
    """Mixin for message event processing."""

    async def _process_message_event(self, room, event):
        """
        Process a message event

        Args:
            room: Room object
            event: Parsed event object
        """
        try:
            sender = getattr(event, "sender", None)
            if not isinstance(sender, str) or not sender:
                logger.warning(
                    f"room timeline 事件缺少 sender，跳过：event_id={getattr(event, 'event_id', '<unknown>')}"
                )
                return

            # Check if message is encrypted
            event_type = event.event_type
            event_content = event.content

            # Handle encrypted messages first
            if event_type == M_ROOM_ENCRYPTED or event_content.get("algorithm"):
                if self.e2ee_manager:
                    algorithm = event_content.get("algorithm")
                    logger.debug(f"检测到加密事件，算法：{algorithm}")

                    # 尝试解密
                    decrypted = await self.e2ee_manager.decrypt_event(
                        event_content,
                        sender,
                        room.room_id,
                        event_id=getattr(event, "event_id", None),
                    )
                    if decrypted:
                        decrypted_content = dict(decrypted.get("content", {}) or {})
                        # Relation metadata for encrypted relation/verification
                        # events is often carried in the cleartext envelope.  Keep
                        # it before reparsing so edits, threads, live-message final
                        # updates, and verification commitment calculations all see
                        # the same m.relates_to data as plaintext events.
                        cleartext_relates_to = event_content.get("m.relates_to")
                        if (
                            cleartext_relates_to
                            and "m.relates_to" not in decrypted_content
                        ):
                            decrypted_content["m.relates_to"] = cleartext_relates_to

                        # 替换事件内容为解密后的内容
                        event.content = decrypted_content
                        event.event_type = decrypted.get("type", M_ROOM_MESSAGE)
                        event.msgtype = event.content.get("msgtype", "")
                        event.body = event.content.get("body", "")
                        logger.debug(
                            f"成功解密消息 (room_id={room.room_id}, event_id={event.event_id}, algorithm={algorithm})"
                        )

                        # Check if decrypted message is a verification event (request or other steps)
                        is_verification = (
                            event.event_type.startswith("m.key.verification.")
                            or event.msgtype == "m.key.verification.request"
                        )

                        if is_verification:
                            # Check if it's from self (same user)
                            if sender == self.user_id:
                                # Only process if from a different device
                                from_device = event.content.get("from_device")
                                if (
                                    from_device
                                    and self.e2ee_manager
                                    and from_device == self.e2ee_manager.device_id
                                ):
                                    return  # Ignore own echo

                            logger.debug(
                                f"[EventProcessor] 检测到加密的验证事件 (type={event.event_type})"
                            )

                            # CRITICAL: For encrypted in-room verification events,
                            # m.relates_to is in the CLEARTEXT portion of the encrypted event
                            # (event_content), not in the decrypted payload.
                            # We need to copy it to the decrypted content for commitment calculation.
                            if cleartext_relates_to:
                                event.content["m.relates_to"] = cleartext_relates_to

                            # Reconstruct event_data for verification handler
                            verification_event = {
                                "type": event.event_type,
                                "sender": sender,
                                "event_id": event.event_id,
                                "content": event.content,
                            }
                            await self._handle_in_room_verification(
                                room, verification_event
                            )
                            return

                        event = parse_event(
                            {
                                "type": event.event_type,
                                "event_id": event.event_id,
                                "sender": sender,
                                "origin_server_ts": getattr(
                                    event, "origin_server_ts", 0
                                ),
                                "content": event.content,
                                "unsigned": getattr(event, "unsigned", None),
                            },
                            room.room_id,
                        )
                        event_type = event.event_type
                        event_content = event.content
                    else:
                        logger.warning(
                            f"无法解密消息 (room_id={room.room_id}, event_id={event.event_id})"
                        )
                        return
                else:
                    logger.error(f"收到加密消息但 E2EE 未启用 (room_id={room.room_id})")
                    return

            # Ignore messages from self (unless it was a verification request handled above)
            if sender == self.user_id:
                # Double check to ensure we don't process own messages
                logger.debug(f"忽略来自自身的消息：{event.event_id}")
                return

            # Filter historical messages: ignore events before startup
            evt_ts = getattr(event, "origin_server_ts", None)
            if evt_ts is None:
                evt_ts = getattr(event, "server_timestamp", None)
            if evt_ts is not None and evt_ts < (
                self.startup_ts - TIMESTAMP_BUFFER_MS_1000
            ):  # Allow 1s drift
                logger.debug(
                    f"忽略启动前的历史消息："
                    f"id={getattr(event, 'event_id', '<unknown>')} "
                    f"ts={evt_ts} startup={self.startup_ts}"
                )
                return

            # Message deduplication: check if already processed
            if self._is_message_processed(event.event_id):
                logger.debug(f"忽略重复消息：{event.event_id}")
                return

            # MSC4145 / MSC2676: 处理 m.replace 编辑事件
            # 编辑复用原始事件 ID 检测：如果原始消息已被处理，跳过编辑事件
            # 避免 LLM 对同一个消息的编辑版本重复响应。
            # 若原始消息尚未处理，则用 m.new_content 替换事件内容，
            # 让 LLM 看到的是修正后的文本而非 "* 旧文本" 回退。
            relates_to = event_content.get("m.relates_to", {})
            if isinstance(relates_to, dict) and relates_to.get("rel_type") == "m.replace":
                original_event_id = relates_to.get("event_id")
                if original_event_id and self._is_message_processed(original_event_id):
                    logger.debug(
                        f"忽略已处理消息的编辑：{original_event_id} -> {event.event_id}"
                    )
                    return
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

            # Call message callback
            if self.on_message:
                await self._persist_interacted_user(room, event)
                await self.on_message(room, event)
                self._mark_message_processed(event.event_id)

                # Send read receipt after successful processing.
                # When the message is in a thread, pass the thread ID so the
                # read receipt marks the thread as read (MSC3771).
                from ...plugin_config import get_plugin_config as _get_plugin_config
                if _get_plugin_config().send_read_receipt:
                    try:
                        thread_id = None
                        relates_to = event_content.get("m.relates_to", {})
                        if isinstance(relates_to, dict) and relates_to.get("rel_type") == "m.thread":
                            thread_id = relates_to.get("event_id")
                        await self.client.send_read_receipt(
                            room.room_id, event.event_id, thread_id=thread_id
                        )
                        logger.debug(f"已发送事件 {event.event_id} 的已读回执" + (f" (thread={thread_id})" if thread_id else ""))
                    except Exception as e:
                        logger.debug(f"发送已读回执失败：{e}")

        except Exception as e:
            logger.error(f"处理消息事件时出错：{e}")

