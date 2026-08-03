"""Message, sticker, and reaction event parsing branches."""

from ....constants import (
    M_REACTION,
    M_ROOM_MESSAGE,
    MSGTYPE_FILE,
    MSGTYPE_IMAGE,
    MSGTYPE_STICKER,
    MSGTYPE_TEXT,
)
from ..base import MatrixEvent
from ..messages import (
    RoomMessageEvent,
    RoomMessageFile,
    RoomMessageImage,
    RoomMessageText,
)


def parse_message_event(
    event_data: dict, room_id: str, event_type: str, content: dict
) -> MatrixEvent | None:
    """Parse standard message, sticker, and reaction events."""
    if event_type == M_ROOM_MESSAGE:
        msgtype = content.get("msgtype", "")
        if msgtype == MSGTYPE_TEXT:
            return RoomMessageText.from_dict(event_data, room_id)
        if msgtype == MSGTYPE_IMAGE:
            return RoomMessageImage.from_dict(event_data, room_id)
        if msgtype == MSGTYPE_FILE:
            return RoomMessageFile.from_dict(event_data, room_id)
        return RoomMessageEvent.from_dict(event_data, room_id)
    if event_type == MSGTYPE_STICKER:
        # 贴纸事件使用 RoomMessageEvent 结构，设置 msgtype 为 m.sticker
        event = RoomMessageEvent.from_dict(event_data, room_id)
        event.msgtype = MSGTYPE_STICKER
        # 确保 content 中的 msgtype 也被设置（用于接收器处理）
        if "msgtype" not in event.content:
            event.content["msgtype"] = MSGTYPE_STICKER
        return event
    if event_type == M_REACTION:
        reaction = content.get("m.relates_to", {}).get("key", "")
        reaction_content = dict(content)
        reaction_content["msgtype"] = M_REACTION
        reaction_content["body"] = reaction
        event_data = dict(event_data)
        event_data["content"] = reaction_content
        return RoomMessageEvent.from_dict(event_data, room_id)
    return None
