"""Encrypted payload and room detection helpers."""

from astrbot.api import logger


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
