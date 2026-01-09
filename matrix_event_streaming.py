"""
Matrix 流式发送实现
"""

import time
from typing import Any

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Plain, Reply

from .constants import TEXT_TRUNCATE_LENGTH_50
from .plugin_config import get_plugin_config
from .streaming_crypto import (
    check_encrypted_room,
    edit_message_encrypted,
    edit_message_plain,
    send_message_encrypted,
    send_message_plain,
)
from .utils.markdown_utils import markdown_to_html
from .utils.utils import MatrixUtils


async def send_streaming_impl(self, generator, use_fallback: bool = False):
    """Matrix streaming send implementation using message edits."""

    # 检查是否禁用编辑模式（等待完成后一次性发送）
    no_edit_mode = get_plugin_config().streaming_no_edit

    logger.info(
        f"Matrix send_streaming 开始 ({'一次性发送' if no_edit_mode else '编辑模式'})，use_fallback={use_fallback}"
    )
    room_id = self.session_id
    accumulated_text = ""
    non_text_components = []

    edit_interval = 1.0
    last_edit_time = 0.0
    message_event_id = None
    initial_message_sent = False

    reply_to = None
    thread_root = None
    use_thread = False
    original_message_info = None

    first_chain_processed = False

    # 检查是否是加密房间
    e2ee_manager = getattr(self, "e2ee_manager", None)
    is_encrypted_room = check_encrypted_room(e2ee_manager, room_id)

    async def send_message(room_id: str, msg_type: str, content: dict) -> dict:
        """发送消息（自动选择加密/非加密）"""
        if is_encrypted_room:
            return await send_message_encrypted(
                self.client, e2ee_manager, room_id, msg_type, content
            )
        return await send_message_plain(self.client, room_id, msg_type, content)

    async def edit_message(room_id: str, original_event_id: str, new_content: dict):
        """编辑消息（自动选择加密/非加密）"""
        if is_encrypted_room:
            await edit_message_encrypted(
                self.client, e2ee_manager, room_id, original_event_id, new_content
            )
        else:
            await edit_message_plain(
                self.client, room_id, original_event_id, new_content
            )

    async def build_content(text: str, is_streaming: bool = True) -> dict[str, Any]:
        """Build message content for streaming edits."""
        try:
            display_text = text + ("..." if is_streaming else "")
            formatted_body = markdown_to_html(display_text)
        except Exception as e:
            logger.warning(f"Failed to render markdown: {e}")
            display_text = text + ("..." if is_streaming else "")
            formatted_body = display_text.replace("\n", "<br>")

        msg_type = "m.notice" if self.use_notice else "m.text"
        content: dict[str, Any] = {
            "msgtype": msg_type,
            "body": display_text,
            "format": "org.matrix.custom.html",
            "formatted_body": formatted_body,
        }

        if not initial_message_sent and original_message_info and reply_to:
            orig_sender = original_message_info.get("sender", "")
            orig_body = original_message_info.get("body", "")
            if len(orig_body) > TEXT_TRUNCATE_LENGTH_50:
                orig_body = orig_body[:TEXT_TRUNCATE_LENGTH_50] + "..."
            fallback_text = f"> <{orig_sender}> {orig_body}\n\n"
            content["body"] = fallback_text + content["body"]

            fallback_html = MatrixUtils.create_reply_fallback(
                original_body=original_message_info.get("body", ""),
                original_sender=original_message_info.get("sender", ""),
                original_event_id=reply_to,
                room_id=room_id,
            )
            content["formatted_body"] = fallback_html + content["formatted_body"]

        if not initial_message_sent:
            if use_thread and thread_root:
                content["m.relates_to"] = {
                    "rel_type": "m.thread",
                    "event_id": thread_root,
                    "m.in_reply_to": {"event_id": reply_to} if reply_to else None,
                }
            elif reply_to:
                content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

        return content

    chain_count = 0
    try:
        async for chain in generator:
            chain_count += 1
            if isinstance(chain, MessageChain):
                if not first_chain_processed:
                    try:
                        from astrbot.api.message_components import Reply as _Reply

                        for seg in chain.chain:
                            if isinstance(seg, _Reply) and getattr(seg, "id", None):
                                reply_to = str(seg.id)
                                break
                    except Exception:
                        pass

                    if not reply_to:
                        try:
                            from astrbot.api.message_components import Reply as _Reply

                            has_reply_component = any(
                                isinstance(seg, _Reply) for seg in chain.chain
                            )

                            if has_reply_component:
                                try:
                                    whoami = await self.client.whoami()
                                    my_user_id = whoami.get("user_id")

                                    if my_user_id:
                                        messages_resp = await self.client.room_messages(
                                            room_id=room_id,
                                            direction="b",
                                            limit=50,
                                        )

                                        chunk = messages_resp.get("chunk", [])
                                        for event in chunk:
                                            if (
                                                event.get("type") == "m.room.message"
                                                and event.get("sender") == my_user_id
                                                and event.get("content", {}).get(
                                                    "msgtype"
                                                )
                                                == "m.text"
                                            ):
                                                reply_to = event.get("event_id")
                                                logger.debug(
                                                    f"找到自己最近的消息作为回复对象：{reply_to}"
                                                )
                                                break
                                except Exception as e:
                                    logger.debug(f"获取自己最近消息失败：{e}")
                        except Exception as e:
                            logger.debug(f"处理回复模式时出错：{e}")

                    if (
                        not reply_to
                        and self.message_obj
                        and self.message_obj.message_id
                    ):
                        reply_to = str(self.message_obj.message_id)

                    if reply_to:
                        try:
                            resp = await self.client.get_event(room_id, reply_to)
                            if resp:
                                original_message_info = {
                                    "sender": resp.get("sender", ""),
                                    "body": resp.get("content", {}).get("body", ""),
                                }
                                if resp and "content" in resp:
                                    relates_to = resp["content"].get("m.relates_to", {})
                                    if relates_to.get("rel_type") == "m.thread":
                                        thread_root = relates_to.get("event_id")
                                        use_thread = True
                                    elif self.enable_threading:
                                        use_thread = True
                                        thread_root = reply_to
                                    else:
                                        use_thread = False
                                        thread_root = None
                        except Exception as e:
                            logger.warning(f"Failed to get event for threading: {e}")

                    first_chain_processed = True

                for component in chain.chain:
                    if isinstance(component, Plain):
                        accumulated_text += component.text
                    elif not isinstance(component, Reply):
                        non_text_components.append(component)

                current_time = time.time()
                if accumulated_text and not no_edit_mode:
                    # 编辑模式：边生成边发送/编辑
                    if not initial_message_sent:
                        try:
                            content = await build_content(
                                accumulated_text, is_streaming=True
                            )
                            result = await send_message(
                                room_id=room_id,
                                msg_type="m.room.message",
                                content=content,
                            )
                            message_event_id = result.get("event_id")
                            initial_message_sent = True
                            last_edit_time = current_time
                            logger.debug(f"流式消息初始发送成功：{message_event_id}")
                        except Exception as e:
                            logger.error(f"发送初始流式消息失败：{e}")
                    elif (
                        message_event_id
                        and (current_time - last_edit_time) >= edit_interval
                    ):
                        try:
                            new_content = {
                                "msgtype": "m.notice" if self.use_notice else "m.text",
                                "body": accumulated_text + "...",
                                "format": "org.matrix.custom.html",
                                "formatted_body": markdown_to_html(
                                    accumulated_text + "..."
                                ),
                            }
                            await edit_message(
                                room_id=room_id,
                                original_event_id=message_event_id,
                                new_content=new_content,
                            )
                            last_edit_time = current_time
                            logger.debug(
                                f"流式消息编辑成功，当前长度：{len(accumulated_text)}"
                            )
                        except Exception as e:
                            logger.debug(f"编辑流式消息失败（将继续累积）：{e}")

    except Exception as e:
        logger.error(f"流式处理过程中出错：{e}")

    finally:
        logger.info(
            f"流式处理完成，共处理 {chain_count} 个消息链，累积文本长度：{len(accumulated_text)}"
        )

    if accumulated_text:
        try:
            try:
                formatted_body = markdown_to_html(accumulated_text)
            except Exception as e:
                logger.warning(f"Failed to render markdown: {e}")
                formatted_body = accumulated_text.replace("\n", "<br>")

            final_content = {
                "msgtype": "m.notice" if self.use_notice else "m.text",
                "body": accumulated_text,
                "format": "org.matrix.custom.html",
                "formatted_body": formatted_body,
            }

            if initial_message_sent and message_event_id and not no_edit_mode:
                # 编辑模式：编辑已发送的消息
                try:
                    await edit_message(
                        room_id=room_id,
                        original_event_id=message_event_id,
                        new_content=final_content,
                    )
                    logger.info("流式消息最终编辑完成")
                except Exception as e:
                    logger.error(f"最终编辑失败：{e}")
            else:
                # 一次性发送模式或未发送过初始消息
                content = await build_content(accumulated_text, is_streaming=False)
                await send_message(
                    room_id=room_id,
                    msg_type="m.room.message",
                    content=content,
                )
                logger.info("流式消息一次性发送成功")
        except Exception as e:
            logger.error(f"发送最终消息失败 (streaming): {e}")

    for component in non_text_components:
        try:
            temp_chain = MessageChain()
            temp_chain.chain = [component]
            await self.send_with_client(
                self.client,
                temp_chain,
                room_id,
                reply_to=reply_to,
                thread_root=thread_root,
                use_thread=use_thread,
                original_message_info=original_message_info,
                use_notice=self.use_notice,
            )
        except Exception as e:
            logger.error(f"发送非文本组件失败：{e}")

    try:
        await self.client.set_typing(room_id, typing=False)
    except Exception as e:
        logger.debug(f"取消输入通知失败：{e}")

    return None
