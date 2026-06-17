"""
Handler for Matrix VoIP / MatrixRTC (Live) 通话事件。

这些事件不是普通聊天消息，而是以系统事件（OtherMessage）形式呈现，
让 joins/leaves/hangups 等通话状态变化对 AstrBot 工作流可见，
同时不会触发 LLM 自动回复（机器人无法真正参与 WebRTC 媒体）。
"""

from astrbot.api.message_components import Plain

from ...call_events import format_call_event_text, is_call_event_type

__all__ = ["handle_call_event", "is_call_event_type"]


async def handle_call_event(receiver, chain, event, event_type):
    """
    Handle VoIP / MatrixRTC call events (m.call.*, m.rtc.member, call.notify).

    Args:
        receiver: MatrixReceiver instance
        chain: MessageChain to append to
        event: Matrix event object
        event_type: Event type (unused, kept for handler signature parity)
    """
    text = format_call_event_text(event)
    if text:
        chain.chain.append(Plain(text))
