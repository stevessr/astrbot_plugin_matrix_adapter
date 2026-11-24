"""Audio-specific caption policy shared by the handler and STT conversion."""

import html
import re
import unicodedata

from .extraction import _extract_unstable_file

# Exact labels only: never discard a sentence merely containing one of these.
_VOICE_LABELS = frozenset(
    {
        "voice message", "voice recording", "audio message",
        "语音消息", "语音留言", "語音訊息", "語音消息", "語音留言",
        "音声メッセージ", "ボイスメッセージ",
        "음성 메시지", "음성 메시지입니다",
        "message vocal", "sprachnachricht", "mensaje de voz",
        "mensagem de voz", "сообщение голосовое", "голосовое сообщение",
        "رسالة صوتية",
    }
)
_AUDIO_FILENAME = re.compile(
    r"[^\s/\\]+\.(?:ogg|oga|opus|mp3|m4a|aac|wav|flac|amr|webm|aiff|aif|mp4)",
    re.IGNORECASE,
)
_SIMPLE_WRAPPER = re.compile(
    r"<(p|span|div|b|strong|i|em)>\s*(.*?)\s*</\1>",
    re.IGNORECASE | re.DOTALL,
)
_REPLY_TEXT = re.compile(r"\A(?:>[^\r\n]*\r?\n)+\r?\n")
_REPLY_HTML = re.compile(r"\A\s*<mx-reply>.*?</mx-reply>\s*", re.DOTALL | re.IGNORECASE)


def _normalise_label(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _declares_reply(content: dict) -> bool:
    relation = content.get("m.relates_to")
    if not isinstance(relation, dict):
        return False
    reply = relation.get("m.in_reply_to")
    return bool(
        (isinstance(reply, dict) and reply.get("event_id"))
        or (relation.get("rel_type") == "m.thread" and relation.get("event_id"))
    )


def _plain_placeholder(value: str, filename: str | None) -> bool:
    if not value.strip():
        return True
    if filename and value.strip() == filename.strip():
        return True
    if _normalise_label(value) in _VOICE_LABELS:
        return True
    # A distinct filename establishes a caption: do not guess from its suffix.
    return not filename and bool(_AUDIO_FILENAME.fullmatch(value.strip()))


def _simple_html_text(value: str) -> str | None:
    """Accept only plain text or simple presentation wrappers, not links/mentions."""
    value = value.strip()
    while match := _SIMPLE_WRAPPER.fullmatch(value):
        value = match.group(2).strip()
    if "<" in value or ">" in value:
        return None
    return html.unescape(value)


def audio_caption_content(content: dict) -> dict | None:
    """Return the actual caption (with reply fallback removed), or None.

    Without an explicit filename, preserve ambiguous prose instead of assuming
    every body is a filename. Exact generated labels remain inherently ambiguous
    when a sender intentionally uses the same words as a caption.
    """
    body = content.get("body")
    body = body if isinstance(body, str) else ""
    formatted = content.get("formatted_body")
    formatted = formatted if isinstance(formatted, str) else ""
    if _declares_reply(content):
        body = _REPLY_TEXT.sub("", body, count=1)
        formatted = _REPLY_HTML.sub("", formatted, count=1)

    filename = content.get("filename") or _extract_unstable_file(content).get("name")
    filename = filename if isinstance(filename, str) and filename.strip() else None

    if _plain_placeholder(body, filename):
        if not formatted.strip():
            return None
        simple = _simple_html_text(formatted)
        if simple is not None and _plain_placeholder(simple, filename):
            return None

    result = dict(content)
    result["body"] = body
    if "formatted_body" in result:
        result["formatted_body"] = formatted
    return result
