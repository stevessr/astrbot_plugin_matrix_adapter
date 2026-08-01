import time

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.message_components import Reply as _Reply
from astrbot.api.platform import AstrBotMessage, PlatformMetadata

from .constants import (
    M_ROOM_MESSAGE,
    MSGTYPE_NOTICE,
    MSGTYPE_TEXT,
    STREAMING_TYPING_REFRESH_SECONDS,
    STREAMING_TYPING_TIMEOUT_MS,
)
from .matrix_event_send import send_with_client_impl
from .matrix_event_stream import MatrixPlatformEventStreamMixin


class MatrixPlatformEvent(MatrixPlatformEventStreamMixin, AstrMessageEvent):
    """Matrix 平台事件处理器（不依赖 matrix-nio）

    ``send`` 负责普通消息，``send_streaming`` 固定通过 MSC4357
    Live Messages 连续编辑同一条消息。
    """

    def __init__(
        self,
        message_str: str,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        session_id: str,
        client,
        enable_threading: bool = False,
        room_live_messaging_enabled: bool | None = None,
        live_message_update_interval_ms: int = 2000,
        e2ee_manager=None,
        use_notice: bool = False,
        adaptive_thread_reply: bool = True,
        send_typing: bool = False,
    ):
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.client = client  # MatrixHTTPClient instance
        self.enable_threading = enable_threading  # 试验性：是否默认开启嘟文串模式
        # 回复自适应：入站（唤醒）消息位于消息列内时，回复也留在同一消息列。
        # 只跟随已存在的消息列，不会替 enable_threading 新建消息列。
        self.adaptive_thread_reply = adaptive_thread_reply
        # 流式是独立发送接口，无需额外总开关。仅当房间通过
        # MSC4357 状态明确声明 ``enabled: false`` 时退化为普通回复。
        self.live_messages_allowed = room_live_messaging_enabled is not False
        try:
            update_interval_ms = int(live_message_update_interval_ms)
        except (TypeError, ValueError):
            update_interval_ms = 2000
        self.live_message_update_interval_ms = min(
            10000,
            max(1000, update_interval_ms),
        )
        self.e2ee_manager = e2ee_manager
        self.use_notice = use_notice  # 使用 m.notice 而不是 m.text
        # 是否向房间发送「正在输入」状态（插件级开关，默认关闭）。
        # 不能命名为 ``send_typing``：AstrBot 4.26+ 会调用同名的异步
        # 生命周期方法，实例布尔属性会将方法遮蔽成不可调用对象。
        self._send_typing_enabled = bool(send_typing)

        # AstrBot 的分段回复会把 Reply/At 头部组件只放在第一段，之后的
        # ``event.send`` 调用只带 Plain（见 RespondStage）。Matrix 的线程关系
        # 是每条事件独立声明的，因此不能仅依赖当前消息段里的 Reply 组件。
        # 这里保存本次入站事件发送过程中解析出的线程上下文，让后续分段
        # 继续使用同一个线程根，而不会回落到房间时间线。
        self._response_thread_context: dict | None = None

        # 正常情况不覆盖 AstrBot 的流式调度；平台已声明支持
        # send_streaming，只在房间明确禁用时阻止上游产生流。
        if not self.live_messages_allowed:
            self.set_extra("enable_streaming", False)

    def _inbound_event_id(self) -> str | None:
        """本次入站（唤醒）事件的 ``event_id``。"""

        source_event_id = getattr(self.message_obj, "message_id", None)
        if not source_event_id:
            raw_message = getattr(self.message_obj, "raw_message", None)
            if isinstance(raw_message, dict):
                source_event_id = raw_message.get("event_id")
            else:
                source_event_id = getattr(raw_message, "event_id", None)
        return str(source_event_id) if source_event_id else None

    def _inbound_thread_root(self) -> str | None:
        """入站事件所在消息列的根事件；不在消息列内时返回 ``None``。"""

        raw_message = getattr(self.message_obj, "raw_message", None)
        if isinstance(raw_message, dict):
            content = raw_message.get("content", {})
        else:
            content = getattr(raw_message, "content", {})
        if not isinstance(content, dict):
            return None
        relation = content.get("m.relates_to")
        if not isinstance(relation, dict):
            return None
        if relation.get("rel_type") != "m.thread":
            return None
        thread_root = relation.get("event_id")
        return str(thread_root) if thread_root else None

    @staticmethod
    async def send_with_client(
        client,
        message_chain: MessageChain,
        room_id: str,
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        original_message_info: dict | None = None,
        e2ee_manager=None,
        max_upload_size: int | None = None,
        use_notice: bool = False,
        thread_is_falling_back: bool | None = None,
    ) -> int:
        """使用提供的 client 将指定消息链发送到指定房间。"""
        return await send_with_client_impl(
            client=client,
            message_chain=message_chain,
            room_id=room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=e2ee_manager,
            max_upload_size=max_upload_size,
            use_notice=use_notice,
            thread_is_falling_back=thread_is_falling_back,
        )

    async def send(self, message_chain: MessageChain):
        """发送消息"""
        self.message_chain = message_chain
        # Matrix 的 room_id 即为会话 ID
        room_id = self.session_id

        is_fc_boundary = message_chain.type in {"tool_call", "tool_direct_result"}
        if is_fc_boundary:
            try:
                has_reply = any(
                    isinstance(seg, _Reply) for seg in message_chain.chain or []
                )
                reply_id = getattr(self.message_obj, "message_id", None)
                sender_id = getattr(
                    getattr(self.message_obj, "sender", None),
                    "user_id",
                    None,
                )
                if not has_reply and reply_id:
                    message_chain.chain.insert(
                        0,
                        _Reply(id=reply_id, sender_id=sender_id),
                    )
            except Exception:
                logger.debug(f"FC 边界 Reply 处理失败")

        # 检查是否需要使用嘟文串模式
        reply_to = None
        thread_root = None
        use_thread = False
        reused_thread_context = False
        original_message_info = None
        has_reply_component = False
        thread_is_falling_back = False

        # 尝试从消息链中提取 Reply 段
        try:
            has_reply_component = any(
                isinstance(seg, _Reply) for seg in message_chain.chain
            )
            for seg in message_chain.chain:
                if isinstance(seg, _Reply) and getattr(seg, "id", None):
                    reply_to = str(seg.id)
                    break
        except Exception:
            logger.debug(f"提取 Reply 组件失败")

        # 分段回复的后续消息没有 Reply 组件。优先复用本次事件前一段已经
        # 解析好的线程上下文；如果没有上下文且启用了线程，则使用本次入站
        # 事件作为回复目标，使"关闭引用 + 开启消息串"仍能创建线程。
        if not reply_to:
            context = self._response_thread_context
            if isinstance(context, dict) and context.get("use_thread"):
                reply_to = context.get("reply_to")
                thread_root = context.get("thread_root")
                use_thread = bool(thread_root)
                original_message_info = context.get("original_message_info")
                thread_is_falling_back = bool(
                    context.get("thread_is_falling_back", False)
                )
                reused_thread_context = use_thread

        # 如果没有找到回复对象，但消息链中包含 Reply 组件（表示开启了回复模式）
        # 则尝试获取自己最近发送的消息作为回复对象
        if not reply_to:
            try:
                if has_reply_component:
                    # 直接使用已缓存的 user_id（登录时已设置），无需额外 API 调用
                    my_user_id = getattr(self.client, "user_id", None)

                    if my_user_id:
                        # 节流：每房间每 5 秒最多一次回退查找
                        now = time.time()
                        last_lookup = getattr(self, '_reply_fallback_cache', {}).get(room_id, 0)
                        if now - last_lookup < 5.0:
                            pass  # 跳过
                        else:
                            try:
                                # 获取房间最近的消息
                                messages_resp = await self.client.room_messages(
                                    room_id=room_id,
                                    direction="b",  # 向后获取（最新的消息）
                                    limit=50,  # 获取最近 50 条消息
                                )

                                # 查找自己最近发送的消息
                                chunk = messages_resp.get("chunk", [])
                                for event in chunk:
                                    if (
                                        event.get("type") == M_ROOM_MESSAGE
                                        and event.get("sender") == my_user_id
                                        and event.get("content", {}).get("msgtype")
                                        in (MSGTYPE_TEXT, MSGTYPE_NOTICE)
                                    ):
                                        reply_to = event.get("event_id")
                                        logger.debug(
                                            f"找到自己最近的消息作为回复对象：{reply_to}"
                                        )
                                        break
                            except Exception as e:
                                logger.debug(f"获取自己最近消息失败：{e}")
                            finally:
                                if not hasattr(self, '_reply_fallback_cache'):
                                    self._reply_fallback_cache = {}
                                self._reply_fallback_cache[room_id] = now
            except Exception as e:
                logger.debug(f"处理回复模式时出错：{e}")

        # 回复自适应：入站（唤醒）消息位于消息列内时，本次回复必须留在同一
        # 消息列，而不是回落到房间时间线。
        inbound_thread_root = (
            self._inbound_thread_root() if self.adaptive_thread_reply else None
        )

        # 没有 Reply 组件时（例如关闭 AstrBot 全局引用）直接使用入站事件
        # 作为线程目标。放在上面的兼容查询之后，保留空 Reply 组件原有的
        # "尝试回复最近一条 bot 消息"行为。
        if not reply_to and (self.enable_threading or inbound_thread_root):
            source_event_id = self._inbound_event_id()
            if source_event_id:
                reply_to = source_event_id
                # Keep the target for thread continuity without rendering it
                # as an explicit reply when AstrBot quote mode is disabled.
                thread_is_falling_back = True

        # 如果有回复，检查是否需要使用嘟文串模式
        if reply_to and not reused_thread_context:
            try:
                # 配置开启线程时，即使事件查询失败，也可以先按当前回复
                # 目标创建线程；如果查询到的目标本身已在其他线程中，下面
                # 再用真实线程根覆盖这个默认值。
                if self.enable_threading:
                    use_thread = True
                    thread_root = reply_to

                # 获取被回复消息的事件信息
                resp = await self.client.get_event(room_id, reply_to)
                if resp:
                    # 提取原始消息信息用于 fallback
                    original_message_info = {
                        "sender": resp.get("sender", ""),
                        "body": resp.get("content", {}).get("body", ""),
                        "mentions": resp.get("content", {}).get("m.mentions", {}),
                    }

                    # 检查被回复消息是否已经是嘟文串的一部分
                    if "content" in resp:
                        relates_to = resp["content"].get("m.relates_to", {})
                        if not isinstance(relates_to, dict):
                            relates_to = {}
                        if relates_to.get("rel_type") == "m.thread":
                            # 如果是嘟文串的一部分，获取根消息 ID
                            thread_root = relates_to.get("event_id") or reply_to
                            use_thread = True
                        elif self.enable_threading:
                            # 试验性功能：如果启用嘟文串模式，创建新的嘟文串
                            use_thread = True
                            thread_root = reply_to  # 将被回复的消息作为嘟文串根
                        else:
                            # 如果不是嘟文串，不要强制开启嘟文串模式，使用标准回复
                            use_thread = False
                            thread_root = None
            except Exception as e:
                logger.warning(f"Failed to get event for threading: {e}")

        # 回复自适应最终裁定：入站消息在消息列内时，锁定该消息列作为线程根，
        # 覆盖上面按回复目标推导出的结果（包括查询失败或目标不在消息列内）。
        if inbound_thread_root and reply_to and not reused_thread_context:
            inbound_event_id = self._inbound_event_id()
            if (
                inbound_event_id
                and reply_to != inbound_event_id
                and thread_root != inbound_thread_root
            ):
                # 回复目标位于本消息列之外，Matrix 不允许跨消息列引用，
                # 因此把引用目标退回到入站消息本身。
                reply_to = inbound_event_id
                thread_is_falling_back = True
            thread_root = inbound_thread_root
            use_thread = True

        # 发送前记住线程上下文。第一段可能带 Reply，后续分段没有 Reply，
        # 但每一段仍必须携带 m.thread 关系。只缓存真正的线程关系，普通
        # m.in_reply_to 回复保持 AstrBot 原本的行为。
        if use_thread and thread_root:
            self._response_thread_context = {
                "reply_to": reply_to or thread_root,
                "thread_root": thread_root,
                "use_thread": True,
                "original_message_info": original_message_info,
                "thread_is_falling_back": thread_is_falling_back,
            }
        elif reply_to and not reused_thread_context:
            # 当前调用明确指定了普通回复时，不要把上一次线程上下文泄漏
            # 到一个新的、非线程回复中。
            self._response_thread_context = None

        await MatrixPlatformEvent.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            e2ee_manager=self.e2ee_manager,
            use_notice=self.use_notice,
            thread_is_falling_back=thread_is_falling_back,
        )

        # FC 边界：清除线程上下文，后续回复另开新消息而非接续
        if is_fc_boundary:
            self._response_thread_context = None

        return await super().send(message_chain)

    async def react(self, emoji: str):
        """对消息添加表情回应。"""
        try:
            event_id = getattr(self.message_obj, "message_id", None)
            if not event_id and hasattr(self.message_obj, "raw_message"):
                event_id = getattr(self.message_obj.raw_message, "event_id", None)
            if not event_id:
                logger.debug("无法添加反应：缺少 event_id")
                return
            await self.client.send_reaction(self.session_id, event_id, emoji)
        except Exception as e:
            logger.debug(f"发送表情反应失败：{e}")

    async def delete(self, reason: str | None = None, event_id: str | None = None):
        """删除（撤回）消息。"""
        try:
            target_event_id = event_id or getattr(self.message_obj, "message_id", None)
            if not target_event_id and hasattr(self.message_obj, "raw_message"):
                target_event_id = getattr(
                    self.message_obj.raw_message, "event_id", None
                )
            if not target_event_id:
                logger.warning("无法删除消息：缺少 event_id")
                return
            await self.client.redact_event(
                self.session_id, str(target_event_id), reason=reason
            )
        except Exception as e:
            logger.error(f"删除消息失败：{e}")