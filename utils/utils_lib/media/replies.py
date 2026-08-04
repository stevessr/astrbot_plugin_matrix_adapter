"""Matrix rich-reply fallback generation and stripping."""

import html
from urllib.parse import quote


class MatrixUtilsMediaReplyMixin:
    """Build and strip Matrix rich-reply fallback quote blocks."""

    @staticmethod
    def create_reply_fallback(
        original_body: str, original_sender: str, original_event_id: str, room_id: str
    ) -> str:
        """
        生成 Matrix 回复引用 (fallback)
        格式参考：https://spec.matrix.org/latest/client-server-api/#fallbacks-for-rich-replies
        <mx-reply>
          <blockquote>
            <a href="https://matrix.to/#/!somewhere:example.org/$event:example.org">In reply to</a>
            <a href="https://matrix.to/#/@alice:example.org">@alice:example.org</a>
            <br />
            Message content
          </blockquote>
        </mx-reply>
        """
        # 防止 original_body 为空或其他类型
        if not original_body:
            original_body = ""

        # 简单截断过长内容，避免引用过大
        if len(original_body) > 200:
            original_body = original_body[:200] + "..."

        # 转义 HTML 特殊字符，避免注入；matrix.to path segments 也要
        # percent-encode，避免 room/event/user id 中的 /、#、空格等破坏链接。
        safe_body = html.escape(original_body).replace("\n", "<br />")
        safe_sender = html.escape(str(original_sender or ""))
        room_path = quote(str(room_id or ""), safe="")
        event_path = quote(str(original_event_id or ""), safe="")
        sender_path = quote(str(original_sender or ""), safe="")

        return (
            f"<mx-reply>"
            f"<blockquote>"
            f'<a href="https://matrix.to/#/{room_path}/{event_path}">In reply to</a> '
            f'<a href="https://matrix.to/#/{sender_path}">{safe_sender}</a>'
            f"<br />{safe_body}"
            f"</blockquote>"
            f"</mx-reply>"
        )

    @staticmethod
    def strip_reply_fallback(body: str) -> str:
        """
        去除 Matrix 回复的 fallback 内容 (引用文本)
        通常格式为：
        > <@user:server> message

        或者
        > <@user:server>
        > message
        """
        if not body:
            return ""
        # 1. 匹配标准 fallback 格式：以 > <@user:id> 开头，可能跨越多行
        # 匹配模式：
        # ^> <.*?>.*?\n\n
        # 或者简单的多行 > 开头的块

        # 常见的 fallback 结构是：
        # > <@sender:server> original message...
        # > ... continued ...
        #
        # new message

        # 我们尝试移除所有连续的以 > 开头的行，以及随后的空行

        lines = body.split("\n")
        # 统计开头的 fallback 行数
        fallback_line_count = 0

        for line in lines:
            if line.startswith(">") or (fallback_line_count > 0 and line.strip() == ""):
                fallback_line_count += 1
            else:
                break

        if fallback_line_count > 0:
            # 移除 fallback 行
            return "\n".join(lines[fallback_line_count:]).lstrip()

        return body
