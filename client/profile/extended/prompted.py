"""MSC4495 prompted presence account-data operations."""

from typing import Any

from ....constants import M_PRESENCE_PROMPTED, MSC4495_PRESENCE_PROMPTED


class PresencePromptedMixin:
    """Read and update prompted presence user/room lists."""

    async def get_presence_prompted(self) -> dict[str, Any]:
        """读取 ``m.presence.prompted`` account data（MSC4495）。"""
        for type_key in (M_PRESENCE_PROMPTED, MSC4495_PRESENCE_PROMPTED):
            try:
                data = await self.get_global_account_data(type_key)
            except Exception:
                continue
            content = data.get("content") if isinstance(data, dict) else None
            if isinstance(content, dict) and content:
                return content
            if isinstance(data, dict) and data and "content" not in data:
                return data
        return {"users": [], "rooms": []}

    async def set_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        """覆盖写入 ``m.presence.prompted``（MSC4495），同时双栈写入。"""
        content: dict[str, Any] = {
            "users": list(users) if users is not None else [],
            "rooms": list(rooms) if rooms is not None else [],
        }
        await self.set_global_account_data(M_PRESENCE_PROMPTED, content)
        try:
            await self.set_global_account_data(MSC4495_PRESENCE_PROMPTED, content)
        except Exception as e:
            from astrbot.api import logger

            logger.debug(f"Failed to set unstable presence.prompted: {e}")
        return content

    async def _modify_presence_prompted(
        self,
        *,
        add_users: list[str] | None = None,
        add_rooms: list[str] | None = None,
        remove_users: list[str] | None = None,
        remove_rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        current = await self.get_presence_prompted()
        users_list: list[str] = list(current.get("users") or [])
        rooms_list: list[str] = list(current.get("rooms") or [])

        def _add(target: list[str], additions: list[str] | None) -> None:
            if not additions:
                return
            existing = set(target)
            for item in additions:
                if item and item not in existing:
                    target.append(item)
                    existing.add(item)

        def _remove(target: list[str], removals: list[str] | None) -> None:
            if not removals:
                return
            remove_set = set(removals)
            target[:] = [x for x in target if x not in remove_set]

        _add(users_list, add_users)
        _add(rooms_list, add_rooms)
        _remove(users_list, remove_users)
        _remove(rooms_list, remove_rooms)
        return await self.set_presence_prompted(users=users_list, rooms=rooms_list)

    async def add_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        """把 user/room 加入 ``m.presence.prompted`` 数组（去重，MSC4495）。"""
        return await self._modify_presence_prompted(add_users=users, add_rooms=rooms)

    async def remove_presence_prompted(
        self,
        *,
        users: list[str] | None = None,
        rooms: list[str] | None = None,
    ) -> dict[str, Any]:
        """把 user/room 从 ``m.presence.prompted`` 数组移除（MSC4495）。"""
        return await self._modify_presence_prompted(
            remove_users=users, remove_rooms=rooms
        )


__all__ = ["PresencePromptedMixin"]
