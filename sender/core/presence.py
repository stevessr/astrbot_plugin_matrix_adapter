"""Selective-presence sender operations (MSC4495)."""


class SenderPresenceMixin:
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


__all__ = ["SenderPresenceMixin"]
