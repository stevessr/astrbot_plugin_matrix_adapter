"""Dispatch individual AstrBot message components to Matrix encoders."""

from astrbot.api import logger
from astrbot.api.message_components import (
    RPS,
    At,
    Contact,
    Dice,
    Face,
    File,
    Forward,
    Image,
    Json,
    Location,
    Music,
    Node,
    Nodes,
    Plain,
    Poke,
    Reply,
    Shake,
    Share,
    Unknown,
    Video,
)

from ....constants import (
    M_POLL,
    M_POLL_KIND_DISCLOSED,
    M_POLL_START,
    MATRIX_HTML_FORMAT,
    MSGTYPE_EMOTE,
)
from ...events import (
    send_at,
    send_audio,
    send_contact,
    send_dice,
    send_file,
    send_image,
    send_location,
    send_music,
    send_plain,
    send_poll,
    send_rps,
    send_shake,
    send_share,
    send_sticker,
    send_video,
)
from ...events.common import send_content
from ...events.record_component import coerce_record_component, is_record_component
from ..content import (
    _fallback_content_for_segment,
    _is_media_security_validation_error,
    _is_poll_component,
    _is_sticker_component,
    _truncate_text,
)
from .context import SendContext


async def send_segments(context: SendContext) -> int:
    """Dispatch all prepared components and return the successful count."""
    client = context.client
    chain_to_send = context.chain_to_send
    room_id = context.room_id
    reply_to = context.reply_to
    thread_root = context.thread_root
    use_thread = context.use_thread
    original_message_info = context.original_message_info
    e2ee_manager = context.e2ee_manager
    upload_size_limit = context.upload_size_limit
    use_notice = context.use_notice
    thread_is_falling_back = context.thread_is_falling_back
    is_encrypted_room = context.is_encrypted_room

    sent_count = 0
    for segment in chain_to_send:
        if isinstance(segment, Reply):
            continue
        if isinstance(segment, Plain):
            try:
                await send_plain(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    original_message_info,
                    is_encrypted_room,
                    e2ee_manager,
                    use_notice,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送文本消息失败：{e}")

        elif isinstance(segment, Image):
            try:
                await send_image(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                    thread_is_falling_back,
                )
                sent_count += 1
            except ValueError as e:
                if _is_media_security_validation_error(e):
                    logger.warning(f"跳过图片消息（媒体校验失败）：{e}")
                else:
                    logger.error(f"发送图片消息失败：{e}")
            except Exception as e:
                logger.error(f"发送图片消息失败：{e}")

        elif isinstance(segment, At):
            try:
                await send_at(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back,
                    use_notice=use_notice,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理 @ 消息过程出错：{e}")

        elif isinstance(segment, File):
            try:
                await send_file(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理文件消息过程出错：{e}")

        elif isinstance(segment, Location):
            try:
                await send_location(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理位置消息过程出错：{e}")

        elif isinstance(segment, Share):
            try:
                await send_share(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back,
                    use_notice=use_notice,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理分享消息过程出错：{e}")

        elif isinstance(segment, Music):
            try:
                await send_music(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                    thread_is_falling_back,
                    use_notice=use_notice,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理音乐消息过程出错：{e}")

        elif _is_poll_component(segment):
            try:
                # 仅记录投票摘要与选项数量，避免在日志中泄露完整选项列表
                question_summary = _truncate_text(
                    getattr(segment, "question", "") or "", max_len=120
                )
                answers_count = len(getattr(segment, "answers", []) or [])
                logger.debug(
                    f"发送投票消息：question={question_summary}, answers_count={answers_count}"
                )
                await send_poll(
                    client,
                    room_id,
                    segment.question,
                    segment.answers,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    max_selections=getattr(segment, "max_selections", 1) or 1,
                    kind=getattr(segment, "kind", None) or M_POLL_KIND_DISCLOSED,
                    event_type=getattr(segment, "event_type", None) or M_POLL_START,
                    poll_key=getattr(segment, "poll_key", None) or M_POLL,
                    fallback_text=getattr(segment, "fallback_text", None),
                    fallback_html=getattr(segment, "fallback_html", None),
                    thread_is_falling_back=thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理投票消息过程出错：{e}")

        elif isinstance(segment, Contact):
            try:
                await send_contact(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back,
                    use_notice=use_notice,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理联系人消息过程出错：{e}")

        elif isinstance(segment, RPS):
            try:
                await send_rps(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back,
                    use_notice=use_notice,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理 RPS 消息过程出错：{e}")

        elif isinstance(segment, Dice):
            try:
                await send_dice(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back,
                    use_notice=use_notice,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理骰子消息过程出错：{e}")

        elif isinstance(segment, Shake):
            try:
                await send_shake(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理震动消息过程出错：{e}")

        elif isinstance(segment, Video):
            try:
                await send_video(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理视频消息过程出错：{e}")

        elif is_record_component(segment):
            try:
                record_segment = coerce_record_component(segment)
                if record_segment is None:
                    logger.error("处理语音消息失败：无法解析 Record 组件内容")
                    continue
                await send_audio(
                    client,
                    record_segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理语音消息过程出错：{e}")

        elif _is_sticker_component(segment):
            try:
                await send_sticker(
                    client,
                    segment,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    upload_size_limit,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送 sticker 失败：{e}")
        elif isinstance(segment, Poke):
            try:
                content_data = {"msgtype": MSGTYPE_EMOTE, "body": "pokes"}
                await send_content(
                    client,
                    content_data,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                    thread_is_falling_back=thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送 poke 失败：{e}")
        elif isinstance(
            segment,
            (Face, Forward, Node, Nodes, Json, Unknown),
        ):
            try:
                fallback_text, fallback_html = _fallback_content_for_segment(segment)
                if fallback_html:
                    temp = Plain(
                        text=fallback_text,
                        format=MATRIX_HTML_FORMAT,
                        formatted_body=fallback_html,
                        convert=False,
                    )
                else:
                    temp = Plain(fallback_text)
                await send_plain(
                    client,
                    temp,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    original_message_info,
                    is_encrypted_room,
                    e2ee_manager,
                    use_notice,
                    thread_is_falling_back,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送兼容消息失败：{e}")

    return sent_count
