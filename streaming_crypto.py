"""
流式发送的加密辅助函数
"""

from astrbot.api import logger


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
    client, e2ee_manager, room_id: str, msg_type: str, content: dict
) -> dict:
    """加密并发送消息"""
    try:
        encrypted = await e2ee_manager.encrypt_message(room_id, msg_type, content)
        if encrypted:
            return await client.send_message(
                room_id=room_id,
                msg_type="m.room.encrypted",
                content=encrypted,
            )
        logger.warning("流式发送：加密失败，回退到未加密发送")
    except Exception as e:
        logger.warning(f"流式发送：加密异常 {e}，回退到未加密发送")
    return await client.send_message(room_id=room_id, msg_type=msg_type, content=content)


async def send_message_plain(client, room_id: str, msg_type: str, content: dict) -> dict:
    """发送未加密消息"""
    return await client.send_message(room_id=room_id, msg_type=msg_type, content=content)


async def edit_message_encrypted(
    client, e2ee_manager, room_id: str, original_event_id: str, new_content: dict
):
    """加密并编辑消息"""
    try:
        # 构建编辑事件的完整内容
        edit_content = {
            "msgtype": new_content.get("msgtype", "m.text"),
            "body": f"* {new_content.get('body', '')}",
            "m.new_content": new_content,
            "m.relates_to": {
                "rel_type": "m.replace",
                "event_id": original_event_id,
            },
        }
        if "format" in new_content:
            edit_content["format"] = new_content["format"]
            edit_content["formatted_body"] = f"* {new_content.get('formatted_body', '')}"

        encrypted = await e2ee_manager.encrypt_message(
            room_id, "m.room.message", edit_content
        )
        if encrypted:
            await client.send_message(
                room_id=room_id,
                msg_type="m.room.encrypted",
                content=encrypted,
            )
            return
        logger.warning("流式编辑：加密失败，回退到未加密编辑")
    except Exception as e:
        logger.warning(f"流式编辑：加密异常 {e}，回退到未加密编辑")
    await client.edit_message(
        room_id=room_id,
        original_event_id=original_event_id,
        new_content=new_content,
    )


async def edit_message_plain(
    client, room_id: str, original_event_id: str, new_content: dict
):
    """编辑未加密消息"""
    await client.edit_message(
        room_id=room_id,
        original_event_id=original_event_id,
        new_content=new_content,
    )
