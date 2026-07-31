"""
流式发送的加密辅助函数
"""

from astrbot.api import logger

from .constants import M_ROOM_ENCRYPTED, M_ROOM_MESSAGE, REL_TYPE_REPLACE
from .sender.handlers.common import _copy_cleartext_relates_to


def _encrypted_payload_without_relation(content: dict) -> dict:
    """Keep Matrix relations in the cleartext encrypted-event envelope only."""

    payload = dict(content)
    payload.pop("m.relates_to", None)
    return payload


def check_encrypted_room(e2ee_manager, room_id: str) -> bool:
    """检查房间是否启用加密"""
    if not e2ee_manager:
        return False
    try:
        if e2ee_manager._store and e2ee_manager._store.get_megolm_outbound(room_id):
            logger.debug(f"流式发送：检测到加密房间 {room_id}")
            return True
    except Exception:
        pass
    return False


async def send_message_encrypted(
    client,
    e2ee_manager,
    room_id: str,
    msg_type: str,
    content: dict,
    tracker_metadata: dict | None = None,
) -> dict:
    """加密并发送消息"""
    try:
        encrypted = await e2ee_manager.encrypt_message(
            room_id,
            msg_type,
            _encrypted_payload_without_relation(content),
        )
        if encrypted:
            _copy_cleartext_relates_to(encrypted, content)
            return await client.send_message(
                room_id=room_id,
                msg_type=M_ROOM_ENCRYPTED,
                content=encrypted,
                tracker_metadata=tracker_metadata,
            )
        logger.warning("流式发送：加密失败，回退到未加密发送")
    except Exception as e:
        logger.warning(f"流式发送：加密异常 {e}，回退到未加密发送")
    return await client.send_message(
        room_id=room_id,
        msg_type=msg_type,
        content=content,
        tracker_metadata=tracker_metadata,
    )


async def send_message_plain(
    client,
    room_id: str,
    msg_type: str,
    content: dict,
    tracker_metadata: dict | None = None,
) -> dict:
    """发送未加密消息"""
    return await client.send_message(
        room_id=room_id,
        msg_type=msg_type,
        content=content,
        tracker_metadata=tracker_metadata,
    )


async def edit_message_encrypted(
    client,
    e2ee_manager,
    room_id: str,
    original_event_id: str,
    new_content: dict,
    tracker_metadata: dict | None = None,
    thread_root: str | None = None,
):
    """加密并编辑消息

    ``thread_root`` 非空时按 MSC4145 在 ``m.relates_to`` 中同时携带
    ``m.thread`` 关系，保持编辑聚合在原消息列内。
    """
    try:
        # 构建编辑事件的完整内容
        relates_to: dict = {
            "rel_type": REL_TYPE_REPLACE,
            "event_id": original_event_id,
        }
        if thread_root:
            relates_to["m.thread"] = {"event_id": thread_root}
        edit_content = {
            "msgtype": new_content.get("msgtype", "m.text"),
            "body": f"* {new_content.get('body', '')}",
            "m.new_content": new_content,
            "m.relates_to": relates_to,
        }
        if "format" in new_content:
            edit_content["format"] = new_content["format"]
            edit_content["formatted_body"] = (
                f"* {new_content.get('formatted_body', '')}"
            )

        encrypted = await e2ee_manager.encrypt_message(
            room_id,
            M_ROOM_MESSAGE,
            _encrypted_payload_without_relation(edit_content),
        )
        if encrypted:
            _copy_cleartext_relates_to(encrypted, edit_content)
            await client.send_message(
                room_id=room_id,
                msg_type=M_ROOM_ENCRYPTED,
                content=encrypted,
                tracker_metadata=tracker_metadata,
            )
            return
        logger.warning("流式编辑：加密失败，回退到未加密编辑")
    except Exception as e:
        logger.warning(f"流式编辑：加密异常 {e}，回退到未加密编辑")
    await client.edit_message(
        room_id=room_id,
        original_event_id=original_event_id,
        new_content=new_content,
        tracker_metadata=tracker_metadata,
        thread_root=thread_root,
    )


async def edit_message_plain(
    client,
    room_id: str,
    original_event_id: str,
    new_content: dict,
    tracker_metadata: dict | None = None,
    thread_root: str | None = None,
):
    """编辑未加密消息"""
    msg_type = new_content.get("msgtype") or "m.text"
    await client.edit_message(
        room_id=room_id,
        original_event_id=original_event_id,
        new_content=new_content,
        msg_type=msg_type,
        tracker_metadata=tracker_metadata,
        thread_root=thread_root,
    )
