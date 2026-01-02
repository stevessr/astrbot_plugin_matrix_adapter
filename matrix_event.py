import asyncio
import mimetypes
import time
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.message_components import File, Image, Plain, Reply
from astrbot.api.platform import AstrBotMessage, PlatformMetadata

from .constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES, TEXT_TRUNCATE_LENGTH_50

# Update import: markdown_utils is now in utils.markdown_utils
from .utils.markdown_utils import (
    markdown_to_html,
)
from .utils.utils import compress_image_if_needed


class MatrixPlatformEvent(AstrMessageEvent):
    """Matrix 平台事件处理器（不依赖 matrix-nio）"""

    def __init__(
        self,
        message_str: str,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        session_id: str,
        client,
        enable_threading: bool = False,
        e2ee_manager=None,
        use_notice: bool = False,
    ):
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.client = client  # MatrixHTTPClient instance
        self.enable_threading = enable_threading  # 试验性：是否默认开启嘟文串模式
        self.e2ee_manager = e2ee_manager
        self.use_notice = use_notice  # 使用 m.notice 而不是 m.text

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
    ) -> int:
        """使用提供的 client 将指定消息链发送到指定房间。

        Args:
            client: MatrixHTTPClient 实例
            message_chain: 要发送的消息链
            room_id: 目标房间 ID（Matrix 的 roomId）
            reply_to: 可选，被引用的消息 event_id
            thread_root: 可选，嘟文串根消息的 event_id
            use_thread: 是否使用嘟文串模式回复
            original_message_info: 可选，原始消息信息（用于回复）
            e2ee_manager: 可选，E2EEManager 实例（用于加密消息）
            max_upload_size: 可选，最大上传文件大小（字节），超过此大小将压缩
            use_notice: 是否使用 m.notice 类型发送消息（默认 m.text）

        Returns:
            已发送的消息段数量
        """
        # 使用传入的值或默认值
        upload_size_limit = max_upload_size or DEFAULT_MAX_UPLOAD_SIZE_BYTES

        sent_count = 0

        # 检查房间是否需要加密
        is_encrypted_room = False
        if e2ee_manager:
            try:
                is_encrypted_room = await client.is_room_encrypted(room_id)
                if is_encrypted_room:
                    logger.debug(f"房间 {room_id} 已加密，将使用 E2EE 发送消息")
            except Exception as e:
                logger.debug(f"检查房间加密状态失败：{e}")

        # 若未显式传入 reply_to，则尝试从消息链中提取 Reply 段
        if reply_to is None:
            for seg in message_chain.chain:
                if isinstance(seg, Reply) and getattr(seg, "id", None):
                    reply_to = str(seg.id)
                    break

        # Merge adjacent Plain components
        merged_chain = []
        for segment in message_chain.chain:
            if (
                isinstance(segment, Plain)
                and merged_chain
                and isinstance(merged_chain[-1], Plain)
            ):
                merged_chain[-1].text += segment.text
            else:
                merged_chain.append(segment)

        # Use a temporary chain for iteration
        chain_to_send = merged_chain

        for segment in chain_to_send:
            # Reply 段仅用于标注引用关系，实际发送时跳过
            if isinstance(segment, Reply):
                continue
            if isinstance(segment, Plain):
                # 发送支持 Markdown 渲染的文本消息
                # 根据配置选择消息类型：m.notice 或 m.text
                msg_type = "m.notice" if use_notice else "m.text"
                content = {
                    "msgtype": msg_type,
                    "body": segment.text,
                }

                # 如果有回复引用信息，预处理 body 以包含 fallback (纯文本部分)
                # Matrix 规范建议：body 包含 fallback，formatted_body 包含 HTML fallback
                if original_message_info and reply_to:
                    orig_sender = original_message_info.get("sender", "")
                    orig_body = original_message_info.get("body", "")
                    if len(orig_body) > TEXT_TRUNCATE_LENGTH_50:
                        orig_body = orig_body[:TEXT_TRUNCATE_LENGTH_50] + "..."
                    fallback_text = f"> <{orig_sender}> {orig_body}\n\n"
                    # 这里更新 content["body"]，使其包含引用文本
                    content["body"] = fallback_text + content["body"]

                # 生成 formatted_body - 优先使用 segment 中的，否则从 body 转换
                formatted_body = None
                if hasattr(segment, "formatted_body") and segment.formatted_body:
                    formatted_body = segment.formatted_body
                else:
                    # 从 body 文本生成 HTML 格式
                    try:
                        formatted_body = markdown_to_html(segment.text)
                    except Exception as e:
                        logger.warning(f"Failed to render markdown: {e}")
                        formatted_body = segment.text.replace("\n", "<br>")

                # 添加格式化内容
                if hasattr(segment, "format") and segment.format:
                    content["format"] = segment.format
                else:
                    content["format"] = "org.matrix.custom.html"

                if formatted_body:
                    # 如果有回复引用信息，添加 HTML fallback
                    if original_message_info and reply_to:
                        from .utils.utils import MatrixUtils

                        fallback_html = MatrixUtils.create_reply_fallback(
                            original_body=original_message_info.get("body", ""),
                            original_sender=original_message_info.get("sender", ""),
                            original_event_id=reply_to,
                            room_id=room_id,
                        )
                        formatted_body = fallback_html + formatted_body
                        # 确保 format 字段被设置
                        content["format"] = "org.matrix.custom.html"

                    content["formatted_body"] = formatted_body

                # 处理回复关系
                if use_thread and thread_root:
                    # 使用嘟文串模式
                    content["m.relates_to"] = {
                        "rel_type": "m.thread",
                        "event_id": thread_root,
                        "m.in_reply_to": {"event_id": reply_to} if reply_to else None,
                    }
                elif reply_to:
                    # 普通回复模式
                    content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

                try:
                    # 如果房间已加密，使用 E2EE 加密消息
                    if is_encrypted_room and e2ee_manager:
                        encrypted = await e2ee_manager.encrypt_message(
                            room_id, "m.room.message", content
                        )
                        if encrypted:
                            await client.send_message(
                                room_id=room_id,
                                msg_type="m.room.encrypted",
                                content=encrypted,
                            )
                            sent_count += 1
                        else:
                            logger.warning("加密消息失败，尝试发送未加密消息")
                            await client.send_message(
                                room_id=room_id,
                                msg_type="m.room.message",
                                content=content,
                            )
                            sent_count += 1
                    else:
                        await client.send_message(
                            room_id=room_id, msg_type="m.room.message", content=content
                        )
                        sent_count += 1
                except Exception as e:
                    logger.error(f"发送文本消息失败：{e}")

            elif isinstance(segment, Image):
                try:
                    # 统一转换为本地路径
                    img_path = await segment.convert_to_file_path()
                    filename = Path(img_path).name
                    with open(img_path, "rb") as f:
                        image_data = f.read()

                    # 获取图片尺寸
                    width, height = None, None
                    try:
                        import io

                        from PIL import Image as PILImage

                        with PILImage.open(io.BytesIO(image_data)) as img:
                            width, height = img.size
                    except Exception as e:
                        logger.debug(f"无法获取图片尺寸：{e}")

                    # 猜测内容类型，默认使用 image/png
                    content_type = mimetypes.guess_type(filename)[0] or "image/png"

                    # 如果图片过大，尝试压缩（在线程池中执行以避免阻塞事件循环）
                    logger.debug("开始图像压缩（异步执行）...")
                    (
                        image_data,
                        content_type,
                        was_compressed,
                    ) = await asyncio.get_running_loop().run_in_executor(
                        None,
                        compress_image_if_needed,
                        image_data,
                        content_type,
                        upload_size_limit,
                    )
                    logger.debug("图像压缩完成")
                    if was_compressed:
                        # 更新文件名扩展名为 .jpg
                        filename = Path(filename).stem + ".jpg"
                        # 重新获取压缩后的图片尺寸
                        try:
                            with PILImage.open(io.BytesIO(image_data)) as img:
                                width, height = img.size
                        except Exception as e:
                            logger.debug(f"无法获取压缩后图片尺寸：{e}")

                    upload_resp = await client.upload_file(
                        data=image_data, content_type=content_type, filename=filename
                    )

                    content_uri = upload_resp["content_uri"]

                    # 构建 info 字段
                    info: dict[str, Any] = {
                        "mimetype": content_type,
                        "size": len(image_data),
                    }
                    if width and height:
                        info["w"] = width
                        info["h"] = height

                    content = {
                        "msgtype": "m.image",
                        "body": filename,
                        "url": content_uri,
                        "info": info,
                    }

                    # 处理回复关系
                    if use_thread and thread_root:
                        # 使用嘟文串模式
                        content["m.relates_to"] = {
                            "rel_type": "m.thread",
                            "event_id": thread_root,
                            "m.in_reply_to": {"event_id": reply_to}
                            if reply_to
                            else None,
                        }
                    elif reply_to:
                        # 普通回复模式
                        content["m.relates_to"] = {
                            "m.in_reply_to": {"event_id": reply_to}
                        }

                    # 发送图片消息（支持加密房间）
                    if is_encrypted_room and e2ee_manager:
                        try:
                            encrypted = await e2ee_manager.encrypt_message(
                                room_id, "m.room.message", content
                            )
                            if encrypted:
                                await client.send_message(
                                    room_id=room_id,
                                    msg_type="m.room.encrypted",
                                    content=encrypted,
                                )
                                sent_count += 1
                                logger.debug(f"加密图片消息发送成功，房间：{room_id}")
                            else:
                                logger.warning("加密图片消息失败，尝试发送未加密消息")
                                await client.send_message(
                                    room_id=room_id, msg_type="m.room.message", content=content
                                )
                                sent_count += 1
                        except Exception as encrypt_e:
                            logger.warning(f"加密图片失败：{encrypt_e}，发送未加密消息")
                            await client.send_message(
                                room_id=room_id, msg_type="m.room.message", content=content
                            )
                            sent_count += 1
                    else:
                        await client.send_message(
                            room_id=room_id, msg_type="m.room.message", content=content
                        )
                        sent_count += 1
                    logger.debug(f"图片消息发送成功，房间：{room_id}")
                except Exception as e:
                    logger.error(f"发送图片消息失败：{e}")

            elif isinstance(segment, File):
                try:
                    file_path = await segment.get_file()
                    if not file_path:
                        logger.warning("文件消息没有可用的文件路径或下载失败")
                        continue

                    with open(file_path, "rb") as f:
                        file_data = f.read()

                    filename = Path(file_path).name
                    content_type = "application/octet-stream"

                    upload_resp = await client.upload_file(
                        data=file_data, content_type=content_type, filename=filename
                    )

                    content_uri = upload_resp["content_uri"]
                    content = {
                        "msgtype": "m.file",
                        "body": filename,
                        "url": content_uri,
                        "filename": filename,
                    }

                    # 处理回复关系
                    if use_thread and thread_root:
                        # 使用嘟文串模式
                        content["m.relates_to"] = {
                            "rel_type": "m.thread",
                            "event_id": thread_root,
                            "m.in_reply_to": {"event_id": reply_to}
                            if reply_to
                            else None,
                        }
                    elif reply_to:
                        # 普通回复模式
                        content["m.relates_to"] = {
                            "m.in_reply_to": {"event_id": reply_to}
                        }

                    try:
                        # 发送文件消息（支持加密房间）
                        if is_encrypted_room and e2ee_manager:
                            encrypted = await e2ee_manager.encrypt_message(
                                room_id, "m.room.message", content
                            )
                            if encrypted:
                                await client.send_message(
                                    room_id=room_id,
                                    msg_type="m.room.encrypted",
                                    content=encrypted,
                                )
                                sent_count += 1
                            else:
                                logger.warning("加密文件消息失败，尝试发送未加密消息")
                                await client.send_message(
                                    room_id=room_id, msg_type="m.room.message", content=content
                                )
                                sent_count += 1
                        else:
                            await client.send_message(
                                room_id=room_id, msg_type="m.room.message", content=content
                            )
                            sent_count += 1
                    except Exception as e:
                        logger.error(f"发送文件消息失败：{e}")
                except Exception as e:
                    logger.error(f"处理文件消息过程出错：{e}")

        return sent_count

    async def send(self, message_chain: MessageChain):
        """发送消息"""
        self.message_chain = message_chain
        # Matrix 的 room_id 即为会话 ID
        room_id = self.session_id

        # 检查是否需要使用嘟文串模式
        reply_to = None
        thread_root = None
        use_thread = False

        # 尝试从消息链中提取 Reply 段
        try:
            from astrbot.api.message_components import Reply as _Reply

            for seg in message_chain.chain:
                if isinstance(seg, _Reply) and getattr(seg, "id", None):
                    reply_to = str(seg.id)
                    break
        except Exception:
            pass

        # 如果没有找到回复对象，但消息链中包含 Reply 组件（表示开启了回复模式）
        # 则尝试获取自己最近发送的消息作为回复对象
        if not reply_to:
            try:
                from astrbot.api.message_components import Reply as _Reply

                has_reply_component = any(
                    isinstance(seg, _Reply) for seg in message_chain.chain
                )

                if has_reply_component:
                    # 获取房间当前状态以找到自己的用户 ID
                    try:
                        # 尝试通过客户端获取自己的用户 ID
                        whoami = await self.client.whoami()
                        my_user_id = whoami.get("user_id")

                        if my_user_id:
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
                                    event.get("type") == "m.room.message"
                                    and event.get("sender") == my_user_id
                                    and event.get("content", {}).get("msgtype")
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

        # 如果有回复，检查是否需要使用嘟文串模式
        original_message_info = None
        if reply_to:
            try:
                # 获取被回复消息的事件信息
                resp = await self.client.get_event(room_id, reply_to)
                if resp:
                    # 提取原始消息信息用于 fallback
                    original_message_info = {
                        "sender": resp.get("sender", ""),
                        "body": resp.get("content", {}).get("body", ""),
                    }

                    # 检查被回复消息是否已经是嘟文串的一部分
                    if "content" in resp:
                        relates_to = resp["content"].get("m.relates_to", {})
                        if relates_to.get("rel_type") == "m.thread":
                            # 如果是嘟文串的一部分，获取根消息 ID
                            thread_root = relates_to.get("event_id")
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

        await MatrixPlatformEvent.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            original_message_info=original_message_info,
            use_notice=self.use_notice,
        )

        return await super().send(message_chain)

    async def send_streaming(self, generator, use_fallback: bool = False):
        """Matrix 流式发送 - 使用消息编辑实现实时流式更新

        通过先发送初始消息，然后不断编辑该消息来实现流式输出效果。
        类似于 Telegram/Discord 机器人的实时打字效果。
        """

        logger.info(
            f"Matrix send_streaming 开始 (编辑模式)，use_fallback={use_fallback}"
        )
        room_id = self.session_id
        accumulated_text = ""  # 累积的文本内容
        non_text_components = []  # 非文本组件列表

        # 流式编辑控制参数
        edit_interval = 1.0  # 编辑间隔（秒），避免过于频繁的编辑导致 rate limit
        last_edit_time = 0.0
        message_event_id = None  # 已发送消息的 event_id，用于后续编辑
        initial_message_sent = False

        # 嘟文串相关变量
        reply_to = None
        thread_root = None
        use_thread = False
        original_message_info = None

        # 检查第一个消息链是否包含回复信息
        first_chain_processed = False

        async def build_content(text: str, is_streaming: bool = True) -> dict[str, Any]:
            """构建消息内容"""
            # 生成 formatted_body
            try:
                display_text = text + ("..." if is_streaming else "")
                formatted_body = markdown_to_html(display_text)
            except Exception as e:
                logger.warning(f"Failed to render markdown: {e}")
                display_text = text + ("..." if is_streaming else "")
                formatted_body = display_text.replace("\n", "<br>")

            # 根据配置选择消息类型：m.notice 或 m.text
            msg_type = "m.notice" if self.use_notice else "m.text"
            content: dict[str, Any] = {
                "msgtype": msg_type,
                "body": display_text,
                "format": "org.matrix.custom.html",
                "formatted_body": formatted_body,
            }

            # 如果有回复引用信息，添加 fallback（仅初始消息需要）
            if not initial_message_sent and original_message_info and reply_to:
                orig_sender = original_message_info.get("sender", "")
                orig_body = original_message_info.get("body", "")
                if len(orig_body) > TEXT_TRUNCATE_LENGTH_50:
                    orig_body = orig_body[:TEXT_TRUNCATE_LENGTH_50] + "..."
                fallback_text = f"> <{orig_sender}> {orig_body}\n\n"
                content["body"] = fallback_text + content["body"]

                from .utils.utils import MatrixUtils

                fallback_html = MatrixUtils.create_reply_fallback(
                    original_body=original_message_info.get("body", ""),
                    original_sender=original_message_info.get("sender", ""),
                    original_event_id=reply_to,
                    room_id=room_id,
                )
                content["formatted_body"] = fallback_html + content["formatted_body"]

            # 添加嘟文串支持（仅初始消息需要）
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
                    # 只在第一个消息链中检查回复信息
                    if not first_chain_processed:
                        try:
                            from astrbot.api.message_components import Reply as _Reply

                            for seg in chain.chain:
                                if isinstance(seg, _Reply) and getattr(seg, "id", None):
                                    reply_to = str(seg.id)
                                    break
                        except Exception:
                            pass

                        # 如果没有找到回复对象，但消息链中包含 Reply 组件
                        if not reply_to:
                            try:
                                from astrbot.api.message_components import (
                                    Reply as _Reply,
                                )

                                has_reply_component = any(
                                    isinstance(seg, _Reply) for seg in chain.chain
                                )

                                if has_reply_component:
                                    try:
                                        whoami = await self.client.whoami()
                                        my_user_id = whoami.get("user_id")

                                        if my_user_id:
                                            messages_resp = (
                                                await self.client.room_messages(
                                                    room_id=room_id,
                                                    direction="b",
                                                    limit=50,
                                                )
                                            )

                                            chunk = messages_resp.get("chunk", [])
                                            for event in chunk:
                                                if (
                                                    event.get("type")
                                                    == "m.room.message"
                                                    and event.get("sender")
                                                    == my_user_id
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

                        # 使用原始消息 ID 作为回复目标
                        if (
                            not reply_to
                            and self.message_obj
                            and self.message_obj.message_id
                        ):
                            reply_to = str(self.message_obj.message_id)

                        # 检查是否需要使用嘟文串模式
                        if reply_to:
                            try:
                                resp = await self.client.get_event(room_id, reply_to)
                                if resp:
                                    original_message_info = {
                                        "sender": resp.get("sender", ""),
                                        "body": resp.get("content", {}).get("body", ""),
                                    }
                                    if resp and "content" in resp:
                                        relates_to = resp["content"].get(
                                            "m.relates_to", {}
                                        )
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
                                logger.warning(
                                    f"Failed to get event for threading: {e}"
                                )

                        first_chain_processed = True

                    # 累积消息链中的所有组件
                    for component in chain.chain:
                        if isinstance(component, Plain):
                            accumulated_text += component.text
                        elif not isinstance(component, Reply):
                            non_text_components.append(component)

                    # 流式编辑逻辑
                    current_time = time.time()
                    if accumulated_text:
                        if not initial_message_sent:
                            # 发送初始消息
                            try:
                                content = await build_content(
                                    accumulated_text, is_streaming=True
                                )
                                result = await self.client.send_message(
                                    room_id=room_id,
                                    msg_type="m.room.message",
                                    content=content,
                                )
                                message_event_id = result.get("event_id")
                                initial_message_sent = True
                                last_edit_time = current_time
                                logger.debug(
                                    f"流式消息初始发送成功：{message_event_id}"
                                )
                            except Exception as e:
                                logger.error(f"发送初始流式消息失败：{e}")
                        elif (
                            message_event_id
                            and (current_time - last_edit_time) >= edit_interval
                        ):
                            # 编辑已发送的消息
                            try:
                                new_content = {
                                    "body": accumulated_text + "...",
                                    "format": "org.matrix.custom.html",
                                    "formatted_body": markdown_to_html(
                                        accumulated_text + "..."
                                    ),
                                }
                                await self.client.edit_message(
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

        # 发送或编辑最终的完整文本内容
        if accumulated_text:
            try:
                # 生成最终的 formatted_body（不带省略号）
                try:
                    formatted_body = markdown_to_html(accumulated_text)
                except Exception as e:
                    logger.warning(f"Failed to render markdown: {e}")
                    formatted_body = accumulated_text.replace("\n", "<br>")

                final_content = {
                    "body": accumulated_text,
                    "format": "org.matrix.custom.html",
                    "formatted_body": formatted_body,
                }

                if initial_message_sent and message_event_id:
                    # 最终编辑，去掉省略号
                    try:
                        await self.client.edit_message(
                            room_id=room_id,
                            original_event_id=message_event_id,
                            new_content=final_content,
                        )
                        logger.info("流式消息最终编辑完成")
                    except Exception as e:
                        logger.error(f"最终编辑失败：{e}")
                else:
                    # 如果从未发送过消息（可能累积太快），直接发送完整内容
                    content = await build_content(accumulated_text, is_streaming=False)
                    await self.client.send_message(
                        room_id=room_id,
                        msg_type="m.room.message",
                        content=content,
                    )
                    logger.info("流式消息一次性发送成功")
            except Exception as e:
                logger.error(f"发送最终消息失败 (streaming): {e}")

        # 发送非文本组件（图片、文件等）
        for component in non_text_components:
            try:
                temp_chain = MessageChain()
                temp_chain.chain = [component]
                await MatrixPlatformEvent.send_with_client(
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

        # Stop typing notification after streaming completes
        try:
            await self.client.set_typing(room_id, typing=False)
        except Exception as e:
            logger.debug(f"取消输入通知失败：{e}")

        return await super().send_streaming(generator, use_fallback)
