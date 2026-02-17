"""
Matrix adapter send helpers.
"""

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import Plain, Reply

from .constants import DEFAULT_TYPING_TIMEOUT_MS, MATRIX_HTML_FORMAT
from .utils.markdown_utils import markdown_to_html


class MatrixAdapterSendMixin:
    async def send_by_session(
        self, session, message_chain: MessageChain, reply_to: str = None
    ):
        try:
            room_id = session.session_id
            thread_root = None
            use_thread = False
            original_message_info = None

            try:
                await self.client.set_typing(
                    room_id, typing=True, timeout=DEFAULT_TYPING_TIMEOUT_MS
                )
            except Exception as e:
                logger.debug(f"发送输入通知失败：{e}")

            if reply_to is None:
                try:
                    for seg in message_chain.chain:
                        if isinstance(seg, Reply) and getattr(seg, "id", None):
                            reply_to = str(seg.id)
                            break
                except Exception:
                    pass

            if reply_to:
                try:
                    resp = await self.client.get_event(room_id, reply_to)
                    if resp:
                        original_message_info = {
                            "sender": resp.get("sender", ""),
                            "body": resp.get("content", {}).get("body", ""),
                        }

                        if "content" in resp:
                            relates_to = resp["content"].get("m.relates_to", {})
                            if relates_to.get("rel_type") == "m.thread":
                                thread_root = relates_to.get("event_id")
                                use_thread = True
                            else:
                                use_thread = (
                                    self._matrix_config.enable_threading
                                    if hasattr(self._matrix_config, "enable_threading")
                                    else False
                                )
                                if use_thread:
                                    thread_root = reply_to
                except Exception as e:
                    logger.warning(f"获取事件用于嘟文串失败：{e}")

            header_comps = []
            plain_comps = []
            other_comps = []

            for seg in message_chain.chain:
                if isinstance(seg, Plain):
                    plain_comps.append(seg)
                elif seg.type in ["Reply", "At"]:
                    header_comps.append(seg)
                else:
                    other_comps.append(seg)

            merged_text = "".join(seg.text or "" for seg in plain_comps)

            if merged_text or other_comps:
                new_chain = []

                if merged_text:
                    if (
                        any(
                            x in merged_text
                            for x in ["**", "*", "`", "#", "- ", "> ", "[", "]("]
                        )
                        or reply_to
                    ):
                        html = markdown_to_html(merged_text)
                        new_chain.append(
                            Plain(
                                text=merged_text,
                                format=MATRIX_HTML_FORMAT,
                                formatted_body=html,
                                convert=True,
                            )
                        )
                    else:
                        new_chain.append(Plain(merged_text))

                new_chain.extend(other_comps)

                new_message_chain = MessageChain(new_chain)

                from .matrix_event import MatrixPlatformEvent

                await MatrixPlatformEvent.send_with_client(
                    self.client,
                    new_message_chain,
                    room_id,
                    reply_to=reply_to,
                    thread_root=thread_root,
                    use_thread=use_thread,
                    original_message_info=original_message_info,
                    e2ee_manager=self.e2ee_manager,
                    max_upload_size=self.max_upload_size,
                    use_notice=self._matrix_config.use_notice,
                )

            try:
                await self.client.set_typing(room_id, typing=False)
            except Exception as e:
                logger.debug(f"停止输入通知失败：{e}")
        except Exception as e:
            logger.error(f"通过会话发送消息失败：{e}")

    async def _send_segment(
        self,
        room_id: str,
        segment,
        header_comps: list,
        reply_to: str,
        thread_root: str,
        use_thread: bool,
        original_message_info: dict | None = None,
    ):
        """发送单个消息段落"""
        if isinstance(segment, Plain):
            text = segment.text or ""
            if any(x in text for x in ["**", "*", "`", "#", "- ", "> ", "[", "]("]) or (
                reply_to and len(header_comps) > 0
            ):
                html = markdown_to_html(text)
                processed_segment = Plain(
                    text=text,
                    format=MATRIX_HTML_FORMAT,
                    formatted_body=html,
                    convert=True,
                )
            else:
                processed_segment = segment
        else:
            processed_segment = segment

        chain = (
            [*header_comps, processed_segment] if header_comps else [processed_segment]
        )

        from .matrix_event import MatrixPlatformEvent

        await MatrixPlatformEvent.send_with_client(
            self.client,
            MessageChain(chain),
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=self.e2ee_manager,
            max_upload_size=self.max_upload_size,
            use_notice=self._matrix_config.use_notice,
        )
