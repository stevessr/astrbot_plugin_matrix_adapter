from __future__ import annotations


class SASVerificationManualNotifyRoomsMixin:
    def set_admin_notify_rooms(self, room_ids: list[str] | None):
        """设置管理员验证通知房间列表（用于手动 SAS 验证提示）。"""
        normalized_rooms: list[str] = []
        for room_id in room_ids or []:
            room_text = str(room_id or "").strip()
            if room_text and room_text not in normalized_rooms:
                normalized_rooms.append(room_text)
        self.admin_notify_room_ids = normalized_rooms

    def get_admin_notify_rooms(self) -> list[str]:
        """获取管理员通知房间列表（优先多房间配置，回退单房间配置）。"""
        rooms: list[str] = []
        configured = getattr(self, "admin_notify_room_ids", None)
        if isinstance(configured, list):
            for room_id in configured:
                room_text = str(room_id or "").strip()
                if room_text and room_text not in rooms:
                    rooms.append(room_text)

        fallback_room = str(getattr(self, "admin_notify_room_id", "") or "").strip()
        if fallback_room and fallback_room not in rooms:
            rooms.append(fallback_room)

        return rooms
