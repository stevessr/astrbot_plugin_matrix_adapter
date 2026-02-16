import html
import json

from astrbot.api import logger
from astrbot.api.event import MessageChain
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
    WechatEmoji,
)

from .components import Poll
from .constants import DEFAULT_MAX_UPLOAD_SIZE_BYTES
from .sender.handlers import (
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
from .sender.handlers.common import send_content
from .sender.handlers.record_component import (
    coerce_record_component,
    is_record_component,
)
from .sticker import Sticker


def _is_sticker_component(obj) -> bool:
    """Check if object is a Sticker-like component via duck-typing."""
    if isinstance(obj, Sticker):
        return True
    class_name = type(obj).__name__
    if class_name != "Sticker":
        return False
    required_attrs = ["body", "url", "info", "to_matrix_content"]
    return all(hasattr(obj, attr) for attr in required_attrs)


def _is_poll_component(obj) -> bool:
    """Check if object is a Poll-like component via duck-typing."""
    if isinstance(obj, Poll):
        return True
    class_name = type(obj).__name__
    if class_name != "Poll":
        return False
    required_attrs = ["question", "answers"]
    return all(hasattr(obj, attr) for attr in required_attrs)


def _truncate_text(text: str, max_len: int = 400) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 20] + "... (truncated)"


def _summarize_components(components: list, max_len: int = 300) -> str:
    parts: list[str] = []
    for comp in components or []:
        if isinstance(comp, Plain):
            parts.append(comp.text)
        else:
            parts.append(f"[{type(comp).__name__}]")
    return _truncate_text(" ".join(parts).strip(), max_len=max_len)


def _fallback_content_for_segment(segment) -> tuple[str, str | None]:
    if isinstance(segment, Face):
        return f"[face:{getattr(segment, 'id', '')}]".strip(), None
    if isinstance(segment, Poke):
        poke_type = getattr(segment, "type", "") or ""
        body = f"[poke:{poke_type}]" if poke_type else "[poke]"
        return body, None
    if isinstance(segment, Forward):
        forward_id = getattr(segment, "id", "") or ""
        body = f"[forward:{forward_id}]" if forward_id else "[forward]"
        return body, None
    if isinstance(segment, Node):
        name = getattr(segment, "name", "") or ""
        uin = getattr(segment, "uin", "") or ""
        prefix = " ".join(x for x in [name, f"({uin})" if uin else ""] if x).strip()
        summary = _summarize_components(getattr(segment, "content", []))
        body = " ".join(x for x in [prefix, summary] if x).strip()
        html_body = "<br>".join(
            [html.escape(line) for line in [prefix, summary] if line and line.strip()]
        )
        return f"[node] {body}".strip(), (
            f"<blockquote>{html_body}</blockquote>" if html_body else None
        )
    if isinstance(segment, Nodes):
        nodes = getattr(segment, "nodes", []) or []
        blocks: list[str] = []
        texts: list[str] = []
        for node in nodes:
            name = getattr(node, "name", "") or ""
            uin = getattr(node, "uin", "") or ""
            prefix = " ".join(x for x in [name, f"({uin})" if uin else ""] if x).strip()
            summary = _summarize_components(getattr(node, "content", []))
            body = " ".join(x for x in [prefix, summary] if x).strip()
            if body:
                texts.append(body)
                blocks.append(f"<blockquote>{html.escape(body)}</blockquote>")
        text_body = _truncate_text(" | ".join(texts), max_len=400)
        html_body = "<br>".join(blocks) if blocks else None
        return f"[nodes] {text_body}".strip(), html_body
    if isinstance(segment, Json):
        try:
            payload = json.dumps(segment.data, ensure_ascii=True, indent=2)
        except Exception:
            payload = str(segment.data)
        payload = _truncate_text(payload, max_len=800)
        body = _truncate_text(f"[json] {payload}", max_len=400)
        html_body = f"<pre><code>{html.escape(payload)}</code></pre>"
        return body, html_body
    if isinstance(segment, WechatEmoji):
        md5 = getattr(segment, "md5", "") or ""
        cdnurl = getattr(segment, "cdnurl", "") or ""
        body = " ".join(x for x in [md5, cdnurl] if x).strip()
        return f"[wechat_emoji] {body}".strip(), None
    if isinstance(segment, Unknown):
        text = getattr(segment, "text", "") or "[unknown]"
        return text, None
    return f"[{type(segment).__name__}]", None


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
                )
                sent_count += 1
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
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"处理音乐消息过程出错：{e}")

        elif _is_poll_component(segment):
            try:
                logger.debug(
                    f"发送投票消息：question={segment.question}, answers={segment.answers}"
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
                    kind=getattr(segment, "kind", None) or "m.disclosed",
                    event_type=getattr(segment, "event_type", None)
                    or "org.matrix.msc3381.poll.start",
                    poll_key=getattr(segment, "poll_key", None)
                    or "org.matrix.msc3381.poll.start",
                    fallback_text=getattr(segment, "fallback_text", None),
                    fallback_html=getattr(segment, "fallback_html", None),
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
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送 sticker 失败：{e}")
        elif isinstance(segment, Poke):
            try:
                content_data = {"msgtype": "m.emote", "body": "pokes"}
                await send_content(
                    client,
                    content_data,
                    room_id,
                    reply_to,
                    thread_root,
                    use_thread,
                    is_encrypted_room,
                    e2ee_manager,
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送 poke 失败：{e}")
        elif isinstance(
            segment,
            (
                Face,
                Forward,
                Node,
                Nodes,
                Json,
                Unknown,
                WechatEmoji,
            ),
        ):
            try:
                fallback_text, fallback_html = _fallback_content_for_segment(segment)
                if fallback_html:
                    temp = Plain(
                        text=fallback_text,
                        format="org.matrix.custom.html",
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
                )
                sent_count += 1
            except Exception as e:
                logger.error(f"发送兼容消息失败：{e}")

    return sent_count
