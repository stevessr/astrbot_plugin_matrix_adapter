import asyncio
import mimetypes
from pathlib import Path
from typing import Any

from astrbot.api import logger
from astrbot.api.event import MessageChain
from astrbot.api.message_components import File, Image, Plain, Reply

from .constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES, TEXT_TRUNCATE_LENGTH_50
from .sticker import Sticker
from .utils.markdown_utils import markdown_to_html
from .utils.utils import MatrixUtils, compress_image_if_needed


def _is_sticker_component(obj) -> bool:
    """Check if object is a Sticker-like component via duck-typing."""
    if isinstance(obj, Sticker):
        return True
    class_name = type(obj).__name__
    if class_name != "Sticker":
        return False
    required_attrs = ["body", "url", "info", "to_matrix_content"]
    return all(hasattr(obj, attr) for attr in required_attrs)


async def send_with_client_impl(
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
    """Send a message chain using the provided client."""
    upload_size_limit = max_upload_size or DEFAULT_MAX_UPLOAD_SIZE_BYTES
    sent_count = 0

    # Check if room is encrypted
    is_encrypted_room = False
    if e2ee_manager:
        try:
            is_encrypted_room = await client.is_room_encrypted(room_id)
            if is_encrypted_room:
                logger.debug(f"房间 {room_id} 已加密，将使用 E2EE 发送消息")
        except Exception as e:
            logger.debug(f"检查房间加密状态失败：{e}")

    if reply_to is None:
        for seg in message_chain.chain:
            if isinstance(seg, Reply) and getattr(seg, "id", None):
                reply_to = str(seg.id)
                break

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

    chain_to_send = merged_chain

    for segment in chain_to_send:
        if isinstance(segment, Reply):
            continue
        if isinstance(segment, Plain):
            msg_type = "m.notice" if use_notice else "m.text"
            content = {"msgtype": msg_type, "body": segment.text}

            if original_message_info and reply_to:
                orig_sender = original_message_info.get("sender", "")
                orig_body = original_message_info.get("body", "")
                if len(orig_body) > TEXT_TRUNCATE_LENGTH_50:
                    orig_body = orig_body[:TEXT_TRUNCATE_LENGTH_50] + "..."
                fallback_text = f"> <{orig_sender}> {orig_body}\n\n"
                content["body"] = fallback_text + content["body"]

            formatted_body = None
            if hasattr(segment, "formatted_body") and segment.formatted_body:
                formatted_body = segment.formatted_body
            else:
                try:
                    formatted_body = markdown_to_html(segment.text)
                except Exception as e:
                    logger.warning(f"Failed to render markdown: {e}")
                    formatted_body = segment.text.replace("\n", "<br>")

            if hasattr(segment, "format") and segment.format:
                content["format"] = segment.format
            else:
                content["format"] = "org.matrix.custom.html"

            if formatted_body:
                if original_message_info and reply_to:
                    fallback_html = MatrixUtils.create_reply_fallback(
                        original_body=original_message_info.get("body", ""),
                        original_sender=original_message_info.get("sender", ""),
                        original_event_id=reply_to,
                        room_id=room_id,
                    )
                    formatted_body = fallback_html + formatted_body
                    content["format"] = "org.matrix.custom.html"

                content["formatted_body"] = formatted_body

            if use_thread and thread_root:
                content["m.relates_to"] = {
                    "rel_type": "m.thread",
                    "event_id": thread_root,
                    "m.in_reply_to": {"event_id": reply_to} if reply_to else None,
                }
            elif reply_to:
                content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

            try:
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
                img_path = await segment.convert_to_file_path()
                filename = Path(img_path).name
                with open(img_path, "rb") as f:
                    image_data = f.read()

                width, height = None, None
                try:
                    import io

                    from PIL import Image as PILImage

                    with PILImage.open(io.BytesIO(image_data)) as img:
                        width, height = img.size
                except Exception as e:
                    logger.debug(f"无法获取图片尺寸：{e}")

                content_type = mimetypes.guess_type(filename)[0] or "image/png"

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
                    filename = Path(filename).stem + ".jpg"
                    try:
                        with PILImage.open(io.BytesIO(image_data)) as img:
                            width, height = img.size
                    except Exception as e:
                        logger.debug(f"无法获取压缩后图片尺寸：{e}")

                upload_resp = await client.upload_file(
                    data=image_data, content_type=content_type, filename=filename
                )

                content_uri = upload_resp["content_uri"]

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

                if use_thread and thread_root:
                    content["m.relates_to"] = {
                        "rel_type": "m.thread",
                        "event_id": thread_root,
                        "m.in_reply_to": {"event_id": reply_to} if reply_to else None,
                    }
                elif reply_to:
                    content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

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
                                room_id=room_id,
                                msg_type="m.room.message",
                                content=content,
                            )
                            sent_count += 1
                    except Exception as encrypt_e:
                        logger.warning(f"加密图片失败：{encrypt_e}，发送未加密消息")
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

                if use_thread and thread_root:
                    content["m.relates_to"] = {
                        "rel_type": "m.thread",
                        "event_id": thread_root,
                        "m.in_reply_to": {"event_id": reply_to} if reply_to else None,
                    }
                elif reply_to:
                    content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

                try:
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
                                room_id=room_id,
                                msg_type="m.room.message",
                                content=content,
                            )
                            sent_count += 1
                    else:
                        await client.send_message(
                            room_id=room_id,
                            msg_type="m.room.message",
                            content=content,
                        )
                        sent_count += 1
                except Exception as e:
                    logger.error(f"发送文件消息失败：{e}")
            except Exception as e:
                logger.error(f"处理文件消息过程出错：{e}")

        elif _is_sticker_component(segment):
            try:
                sticker_data = None
                filename = "sticker.png"
                content_type = segment.info.mimetype or "image/png"
                mxc_url = getattr(segment, "mxc_url", None)

                if mxc_url and mxc_url.startswith("mxc://"):
                    content_uri = mxc_url
                else:
                    try:
                        sticker_path = await segment.convert_to_file_path()
                        filename = Path(sticker_path).name
                        with open(sticker_path, "rb") as f:
                            sticker_data = f.read()
                    except ValueError as e:
                        if "MXC URL" in str(e) and segment.url.startswith("mxc://"):
                            content_uri = segment.url
                        else:
                            raise

                    if sticker_data:
                        width, height = segment.info.width, segment.info.height
                        if width is None or height is None:
                            try:
                                import io

                                from PIL import Image as PILImage

                                with PILImage.open(io.BytesIO(sticker_data)) as img:
                                    width, height = img.size
                            except Exception as e:
                                logger.debug(f"无法获取 sticker 尺寸：{e}")

                        guessed_type = mimetypes.guess_type(filename)[0]
                        if guessed_type:
                            content_type = guessed_type

                        upload_resp = await client.upload_file(
                            data=sticker_data,
                            content_type=content_type,
                            filename=filename,
                        )
                        content_uri = upload_resp["content_uri"]

                        segment.mxc_url = content_uri

                        if width and height:
                            segment.info.width = width
                            segment.info.height = height

                content = segment.to_matrix_content(content_uri)

                if use_thread and thread_root:
                    content["m.relates_to"] = {
                        "rel_type": "m.thread",
                        "event_id": thread_root,
                        "m.in_reply_to": {"event_id": reply_to} if reply_to else None,
                    }
                elif reply_to:
                    content["m.relates_to"] = {"m.in_reply_to": {"event_id": reply_to}}

                if is_encrypted_room and e2ee_manager:
                    try:
                        encrypted = await e2ee_manager.encrypt_message(
                            room_id, "m.sticker", content
                        )
                        if encrypted:
                            await client.send_message(
                                room_id=room_id,
                                msg_type="m.room.encrypted",
                                content=encrypted,
                            )
                            sent_count += 1
                            logger.debug(f"加密 sticker 发送成功，房间：{room_id}")
                        else:
                            logger.warning("加密 sticker 失败，尝试发送未加密消息")
                            await client.send_message(
                                room_id=room_id,
                                msg_type="m.sticker",
                                content=content,
                            )
                            sent_count += 1
                    except Exception as encrypt_e:
                        logger.warning(
                            f"加密 sticker 失败：{encrypt_e}，发送未加密消息"
                        )
                        await client.send_message(
                            room_id=room_id,
                            msg_type="m.sticker",
                            content=content,
                        )
                        sent_count += 1
                else:
                    await client.send_message(
                        room_id=room_id,
                        msg_type="m.sticker",
                        content=content,
                    )
                    sent_count += 1
            except Exception as e:
                logger.error(f"发送 sticker 失败：{e}")

    return sent_count
