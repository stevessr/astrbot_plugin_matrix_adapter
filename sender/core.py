"""
Matrix 消息发送组件
"""

from typing import Any

from .room_messaging import SenderRoomMessagingMixin
from .sender_lib import SenderMediaMixin, SenderRoomMixin


class MatrixSender(SenderRoomMessagingMixin, SenderMediaMixin, SenderRoomMixin):
    def __init__(self, client, e2ee_manager=None, *, use_notice: bool = False):
        self.client = client
        self.e2ee_manager = e2ee_manager
        self.use_notice = bool(use_notice)

    async def get_message_context(
        self,
        room_id: str,
        event_id: str,
        *,
        limit: int | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict:
        """Get events before/after a Matrix event."""
        return await self.client.get_event_context(
            room_id=room_id,
            event_id=event_id,
            limit=limit,
            filter=filter,
        )

    async def promote_to_moderator(self, room_id: str, user_id: str) -> dict:
        """Promote a Matrix user to moderator (power level 50)."""
        return await self.client.promote_to_moderator(
            room_id=room_id,
            user_id=user_id,
        )

    async def demote_user(self, room_id: str, user_id: str) -> dict:
        """Demote a Matrix user to the room default power level."""
        return await self.client.demote_user(room_id=room_id, user_id=user_id)

    # --- MSC4495 Selective Presence ---------------------------------------

    async def get_presence_sharing_prefs(self) -> dict:
        """读取 selective presence 配置（MSC4495）。"""
        return await self.client.get_presence_sharing_prefs()

    async def set_presence_sharing_prefs(
        self,
        *,
        share_locally: bool | None = None,
        users: dict[str, str] | None = None,
        rooms: dict[str, str] | None = None,
        servers: dict[str, str] | None = None,
    ) -> dict:
        """写入 selective presence 配置（MSC4495），双栈写入。"""
        return await self.client.set_presence_sharing_prefs(
            share_locally=share_locally,
            users=users,
            rooms=rooms,
            servers=servers,
        )

    async def get_presence_prompted(self) -> dict:
        """读取 presence prompted 列表（MSC4495）。"""
        return await self.client.get_presence_prompted()

    async def set_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict:
        """覆盖写入 presence prompted 列表（MSC4495）。"""
        return await self.client.set_presence_prompted(users=users, rooms=rooms)

    async def add_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict:
        """把 user/room 加入 prompted 列表（去重，MSC4495）。"""
        return await self.client.add_presence_prompted(users=users, rooms=rooms)

    async def remove_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict:
        """把 user/room 从 prompted 列表移除（MSC4495）。"""
        return await self.client.remove_presence_prompted(users=users, rooms=rooms)

    async def get_selective_presence_capability(self) -> bool:
        """探测服务器是否支持 Selective Presence（MSC4495）。"""
        return await self.client.get_selective_presence_capability()

    async def set_room_presence_sharing(self, room_id: str, hint: str) -> dict:
        """写入房间 presence sharing hint（MSC4495），hint 为 'suggest'/'forbid'。"""
        return await self.client.set_room_presence_sharing(room_id=room_id, hint=hint)

    async def get_room_presence_sharing(self, room_id: str) -> str | None:
        """读取房间 presence sharing hint（MSC4495），缺失视为 'forbid'。"""
        return await self.client.get_room_presence_sharing(room_id=room_id)

    @staticmethod
    def _now_ms() -> int:
        import time

        return int(time.time() * 1000)
