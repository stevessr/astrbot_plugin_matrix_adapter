"""
Matrix 消息接收组件
"""

import hashlib
from pathlib import Path

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import *
from astrbot.api.message_components import Image
from astrbot.api.platform import AstrBotMessage
from astrbot.core.platform.astrbot_message import MessageMember
from astrbot.core.platform.message_type import MessageType
from astrbot.core.utils import astrbot_path

# Update import: Client event types are in ..client.event_types
from ..client.event_types import MatrixRoom
from ..constants import REL_TYPE_THREAD
from ..utils.utils import MatrixUtils


class MatrixReceiver:
    def __init__(
        self,
        user_id: str,
        mxc_converter: callable = None,
        bot_name: str = None,
        client=None,
        matrix_config=None,
    ):
        self.user_id = user_id
        self.mxc_converter = mxc_converter
        self.bot_name = bot_name
        self.client = client  # MatrixHTTPClient instance needed for downloading files
        self.matrix_config = matrix_config  # MatrixConfig instance for media settings

    def _get_media_cache_dir(self) -> Path:
        """获取媒体文件缓存目录"""
        if self.matrix_config and hasattr(self.matrix_config, "media_cache_dir"):
            cache_dir = Path(self.matrix_config.media_cache_dir)
        else:
            # 默认缓存目录
            cache_dir = (
                Path(astrbot_path.get_astrbot_data_path()) / "temp" / "matrix_media"
            )

        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir

    def _should_auto_download_media(self, msgtype: str) -> bool:
        """检查是否应该自动下载该类型的媒体文件"""
        # 默认自动下载图片和贴纸
        return msgtype in ["m.image", "m.sticker"]

    async def _download_media_file(
        self, mxc_url: str, filename: str = None, mimetype: str = None
    ) -> Path:
        """下载媒体文件并返回缓存路径"""
        if not self.client:
            raise Exception("No client available for downloading media")

        # 创建缓存键
        cache_key = hashlib.md5(mxc_url.encode()).hexdigest()
        cache_dir = self._get_media_cache_dir()

        # 确定文件扩展名
        if filename:
            ext = Path(filename).suffix
        elif mimetype:
            ext_map = {
                "image/png": ".png",
                "image/jpeg": ".jpg",
                "image/gif": ".gif",
                "image/webp": ".webp",
            }
            ext = ext_map.get(mimetype, ".jpg")
        else:
            ext = ".jpg"

        cache_path = cache_dir / f"{cache_key}{ext}"

        # 检查缓存
        if cache_path.exists() and cache_path.stat().st_size > 0:
            logger.debug(f"Using cached media file: {cache_path}")
            return cache_path

        # 下载文件
        try:
            logger.info(f"Downloading media file: {mxc_url}")
            media_data = await self.client.download_file(mxc_url)
            cache_path.write_bytes(media_data)
            logger.debug(f"Saved media file to cache: {cache_path}")
            return cache_path
        except Exception as e:
            logger.error(f"Failed to download media file {mxc_url}: {e}")
            raise

    async def convert_message(self, room: MatrixRoom, event) -> AstrBotMessage:
        """
        将 Matrix 消息转换为 AstrBot 消息格式
        """
        message = AstrBotMessage()

        # 基础信息
        message.raw_message = event

        # Strip reply fallback from body
        message.message_str = MatrixUtils.strip_reply_fallback(event.body)
        message.session_id = room.room_id
        message.message_id = event.event_id  # Set message ID for replies
        message.self_id = self.user_id  # Set bot's self ID

        # 默认设为群组消息 (Matrix 房间概念)
        # TODO: 未来可根据房间人数判断是否为私聊
        message.type = MessageType.FRIEND_MESSAGE

        # 发送者信息
        sender_id = event.sender
        sender_name = room.members.get(sender_id, sender_id)

        message.sender = MessageMember(
            user_id=sender_id,
            nickname=sender_name,
        )

        # 构建消息链
        chain = MessageChain()

        # 处理回复
        relates_to = event.content.get("m.relates_to", {})
        reply_event_id = None

        # 1. 检查标准的 m.in_reply_to
        if "m.in_reply_to" in relates_to:
            reply_event_id = relates_to["m.in_reply_to"].get("event_id")

        # 2. 检查嘟文串 (Threading) 回复
        if not reply_event_id and relates_to.get("rel_type") == REL_TYPE_THREAD:
            # 在嘟文串中，如果没有显式的 m.in_reply_to，则视为回复根消息或上一条消息
            # 这里简化处理，如果 rel_type 是 m.thread，我们将其视为回复
            reply_event_id = relates_to.get("event_id")

        if reply_event_id:
            # 创建回复组件
            from astrbot.api.message_components import Reply

            # 注意：Reply 组件通常需要完整的消息对象，但这里我们只有 ID
            # AstrBot 的 Reply 组件结构可能需要适配
            reply_comp = Reply(id=reply_event_id)
            chain.chain.append(reply_comp)

            # 尝试获取引用消息中的图片
            if self.client:
                try:
                    original_event = await self.client.get_event(
                        room.room_id, reply_event_id
                    )
                    if original_event:
                        original_content = original_event.get("content", {})
                        original_msgtype = original_content.get("msgtype")

                        # 如果引用的消息是图片，下载并添加到消息链
                        if (
                            original_msgtype == "m.image"
                            and self._should_auto_download_media("m.image")
                        ):
                            original_mxc_url = original_content.get("url")
                            if original_mxc_url:
                                try:
                                    cache_path = await self._download_media_file(
                                        original_mxc_url,
                                        original_content.get("body", "image.jpg"),
                                    )
                                    chain.chain.append(
                                        Image.fromFileSystem(str(cache_path))
                                    )
                                    logger.debug(
                                        f"Added quoted image to chain: {cache_path}"
                                    )
                                except Exception as img_err:
                                    logger.warning(
                                        f"Failed to download quoted image: {img_err}"
                                    )
                except Exception as e:
                    logger.debug(f"Could not fetch original event for reply: {e}")

        # 处理消息内容
        msgtype = event.content.get("msgtype")

        if msgtype == "m.text":
            text = event.body

            # 处理 @提及
            # 简单实现：检查文本是否以 @bot_name 开头
            if self.bot_name and text.startswith(f"@{self.bot_name}"):
                from astrbot.api.message_components import At

                # 移除 @bot_name 前缀
                text = text[len(self.bot_name) + 1 :].lstrip()
                # 添加 At 组件 (self)
                chain.chain.append(At(user_id=self.user_id))  # bot self

            if text:
                chain.chain.append(Plain(text))

        elif msgtype == "m.image":
            mxc_url = event.content.get("url")
            if mxc_url and self.client and self._should_auto_download_media("m.image"):
                try:
                    cache_path = await self._download_media_file(
                        mxc_url, event.content.get("body", "image.jpg")
                    )
                    chain.chain.append(Image.fromFileSystem(str(cache_path)))
                except Exception as e:
                    logger.error(f"Failed to download Matrix image: {e}")
                    # Fallback to plain text
                    chain.chain.append(Plain(f"[图片下载失败：{event.body}]"))
            elif mxc_url and self.mxc_converter:
                # Fallback to URL if no client or auto-download disabled
                http_url = self.mxc_converter(mxc_url)
                chain.chain.append(Image.fromURL(http_url))
            else:
                # No download and no converter fallback
                chain.chain.append(Plain(f"[图片：{event.body}]"))

        elif msgtype == "m.sticker":
            # 贴纸处理：与 m.image 类似
            mxc_url = event.content.get("url")
            if (
                mxc_url
                and self.client
                and self._should_auto_download_media("m.sticker")
            ):
                try:
                    info = event.content.get("info", {})
                    mimetype = info.get("mimetype", "image/png")
                    cache_path = await self._download_media_file(
                        mxc_url, event.content.get("body", "sticker.png"), mimetype
                    )
                    chain.chain.append(Image.fromFileSystem(str(cache_path)))
                except Exception as e:
                    logger.error(f"Failed to download Matrix sticker: {e}")
                    chain.chain.append(Plain(f"[贴纸：{event.body}]"))
            else:
                chain.chain.append(Plain(f"[贴纸：{event.body}]"))

        elif msgtype in ["m.file", "m.audio", "m.video"]:
            # 其他文件类型暂作文本提示处理，或实现 File 组件
            chain.chain.append(Plain(f"[{msgtype}: {event.body}]"))

        else:
            # 未知类型，直接作为文本
            chain.chain.append(
                Plain(event.body or f"[Unknown message type: {msgtype}]")
            )

        message.message = (
            chain.chain
        )  # AstrBotMessage 需要列表格式的消息链 (list[BaseMessageComponent])
        return message
