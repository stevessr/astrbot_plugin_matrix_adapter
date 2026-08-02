"""Message-chain normalization for adapter session sends."""

from astrbot.api.event import MessageChain
from astrbot.api.message_components import Plain

from ...constants import MATRIX_HTML_FORMAT
from ...utils.markdown_utils import markdown_to_html

_MARKDOWN_MARKERS = ("**", "*", "`", "#", "- ", "> ", "[", "](")


def _looks_like_markdown(text: str) -> bool:
    """检测文本是否包含 Markdown 标记特征。"""
    return any(marker in text for marker in _MARKDOWN_MARKERS)


def format_plain_segment(segment, *, reply_to: str | None, has_header: bool):
    """将需要富文本渲染的纯文本段落转换为 Matrix HTML 消息。"""
    if not isinstance(segment, Plain):
        return segment

    text = segment.text or ""
    if _looks_like_markdown(text) or (reply_to and has_header):
        html = markdown_to_html(text)
        return Plain(
            text=text,
            format=MATRIX_HTML_FORMAT,
            formatted_body=html,
            convert=True,
        )
    return segment


def build_message_chain(message_chain, reply_to: str | None = None):
    """合并纯文本段落并保留头部、非文本消息组件。"""
    header_comps = []
    plain_comps = []
    other_comps = []

    for segment in message_chain.chain:
        if isinstance(segment, Plain):
            plain_comps.append(segment)
        elif segment.type in ["Reply", "At"]:
            header_comps.append(segment)
        else:
            other_comps.append(segment)

    merged_text = "".join(segment.text or "" for segment in plain_comps)
    if not (merged_text or other_comps):
        return None

    new_chain = []
    if merged_text:
        new_chain.append(
            format_plain_segment(
                Plain(text=merged_text),
                reply_to=reply_to,
                has_header=bool(header_comps),
            )
        )
    new_chain.extend(other_comps)
    return MessageChain(new_chain)


__all__ = [
    "_looks_like_markdown",
    "build_message_chain",
    "format_plain_segment",
]
