"""
Matrix HTTP Client - User Management Mixin
Provides user management and moderation methods
"""

from typing import Any

from astrbot.api import logger


class UserMixin:
    """User management methods for Matrix client"""

    # ========== User Invitation ==========

    async def invite_user(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Invite a user to a room

        Args:
            room_id: Room ID
            user_id: User ID to invite

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/invite"
        return await self._request("POST", endpoint, data={"user_id": user_id})

    # ========== User Removal ==========

    async def kick_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Kick a user from a room

        Args:
            room_id: Room ID
            user_id: User ID to kick
            reason: Optional reason for kicking

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/kick"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def ban_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """
        Ban a user from a room

        Args:
            room_id: Room ID
            user_id: User ID to ban
            reason: Optional reason for banning

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/ban"
        data: dict[str, Any] = {"user_id": user_id}
        if reason:
            data["reason"] = reason
        return await self._request("POST", endpoint, data=data)

    async def unban_user(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Unban a user from a room

        Args:
            room_id: Room ID
            user_id: User ID to unban

        Returns:
            Empty dict on success
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/unban"
        return await self._request("POST", endpoint, data={"user_id": user_id})

    # ========== Power Levels (Permissions) ==========

    async def get_power_levels(self, room_id: str) -> dict[str, Any]:
        """
        Get power levels for a room

        Args:
            room_id: Room ID

        Returns:
            Power levels state event content
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state/m.room.power_levels/"
        return await self._request("GET", endpoint)

    async def set_power_levels(
        self, room_id: str, power_levels: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Set power levels for a room

        Args:
            room_id: Room ID
            power_levels: Power levels content

        Returns:
            Response with event_id
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state/m.room.power_levels/"
        return await self._request("PUT", endpoint, data=power_levels)

    async def set_user_power_level(
        self, room_id: str, user_id: str, power_level: int
    ) -> dict[str, Any]:
        """
        Set power level for a specific user in a room

        Args:
            room_id: Room ID
            user_id: User ID
            power_level: Power level (0=default, 50=moderator, 100=admin)

        Returns:
            Response with event_id
        """
        # Get current power levels
        current = await self.get_power_levels(room_id)

        # Update user's power level
        if "users" not in current:
            current["users"] = {}
        current["users"][user_id] = power_level

        return await self.set_power_levels(room_id, current)

    async def promote_to_moderator(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Promote a user to moderator (power level 50)

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Response with event_id
        """
        return await self.set_user_power_level(room_id, user_id, 50)

    async def promote_to_admin(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Promote a user to admin (power level 100)

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Response with event_id
        """
        return await self.set_user_power_level(room_id, user_id, 100)

    async def demote_user(self, room_id: str, user_id: str) -> dict[str, Any]:
        """
        Demote a user to default power level (0)

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Response with event_id
        """
        return await self.set_user_power_level(room_id, user_id, 0)

    # ========== User Profile Lookup ==========

    async def get_user_profile(self, user_id: str) -> dict[str, Any]:
        """
        Get full profile for a user

        Args:
            user_id: User ID

        Returns:
            Profile data including displayname and avatar_url
        """
        endpoint = f"/_matrix/client/v3/profile/{user_id}"
        try:
            return await self._request("GET", endpoint, authenticated=False)
        except Exception as e:
            logger.debug(f"Failed to get profile for {user_id}: {e}")
            return {}

    # ========== User Search ==========

    async def search_users(self, search_term: str, limit: int = 10) -> dict[str, Any]:
        """
        Search for users on the homeserver

        Args:
            search_term: Search term
            limit: Maximum number of results

        Returns:
            Search results with user list
        """
        endpoint = "/_matrix/client/v3/user_directory/search"
        data = {"search_term": search_term, "limit": limit}
        return await self._request("POST", endpoint, data=data)

    # ========== Room Member Info ==========

    async def get_room_member(
        self, room_id: str, user_id: str
    ) -> dict[str, Any] | None:
        """
        Get membership info for a specific user in a room

        Args:
            room_id: Room ID
            user_id: User ID

        Returns:
            Member state event content or None if not found
        """
        endpoint = f"/_matrix/client/v3/rooms/{room_id}/state/m.room.member/{user_id}"
        try:
            return await self._request("GET", endpoint)
        except Exception:
            return None

    async def get_room_admins(self, room_id: str) -> list[str]:
        """
        Get list of admin user IDs in a room

        Args:
            room_id: Room ID

        Returns:
            List of admin user IDs (power level >= 100)
        """
        try:
            power_levels = await self.get_power_levels(room_id)
            users = power_levels.get("users", {})
            return [uid for uid, level in users.items() if level >= 100]
        except Exception as e:
            logger.debug(f"Failed to get admins for room {room_id}: {e}")
            return []

    async def get_room_moderators(self, room_id: str) -> list[str]:
        """
        Get list of moderator user IDs in a room

        Args:
            room_id: Room ID

        Returns:
            List of moderator user IDs (power level >= 50)
        """
        try:
            power_levels = await self.get_power_levels(room_id)
            users = power_levels.get("users", {})
            return [uid for uid, level in users.items() if level >= 50]
        except Exception as e:
            logger.debug(f"Failed to get moderators for room {room_id}: {e}")
            return []

    # ========== Ignore List ==========

    async def get_ignored_users(self) -> list[str]:
        """
        Get list of ignored user IDs

        Returns:
            List of ignored user IDs
        """
        try:
            data = await self.get_global_account_data("m.ignored_user_list")
            ignored = data.get("ignored_users", {})
            return list(ignored.keys())
        except Exception:
            return []

    async def ignore_user(self, user_id: str) -> dict[str, Any]:
        """
        Add a user to the ignore list

        Args:
            user_id: User ID to ignore

        Returns:
            Empty dict on success
        """
        # Get current ignored users
        ignored = await self.get_ignored_users()
        if user_id not in ignored:
            ignored.append(user_id)

        # Build ignored_users dict
        ignored_users = {uid: {} for uid in ignored}

        endpoint = (
            f"/_matrix/client/v3/user/{self.user_id}/account_data/m.ignored_user_list"
        )
        return await self._request(
            "PUT", endpoint, data={"ignored_users": ignored_users}
        )

    async def unignore_user(self, user_id: str) -> dict[str, Any]:
        """
        Remove a user from the ignore list

        Args:
            user_id: User ID to unignore

        Returns:
            Empty dict on success
        """
        # Get current ignored users
        ignored = await self.get_ignored_users()
        if user_id in ignored:
            ignored.remove(user_id)

        # Build ignored_users dict
        ignored_users = {uid: {} for uid in ignored}

        endpoint = (
            f"/_matrix/client/v3/user/{self.user_id}/account_data/m.ignored_user_list"
        )
        return await self._request(
            "PUT", endpoint, data={"ignored_users": ignored_users}
        )

    # ========== Room Creation with Invite ==========

    async def create_dm_room(
        self, user_id: str, name: str | None = None
    ) -> dict[str, Any]:
        """
        Create a direct message room with a user

        Args:
            user_id: User ID to create DM with
            name: Optional room name

        Returns:
            Response with room_id
        """
        data: dict[str, Any] = {
            "invite": [user_id],
            "is_direct": True,
            "preset": "trusted_private_chat",
        }
        if name:
            data["name"] = name

        endpoint = "/_matrix/client/v3/createRoom"
        response = await self._request("POST", endpoint, data=data)

        # Update m.direct account data
        room_id = response.get("room_id")
        if room_id:
            try:
                direct_data = await self.get_global_account_data("m.direct")
                if user_id not in direct_data:
                    direct_data[user_id] = []
                if room_id not in direct_data[user_id]:
                    direct_data[user_id].append(room_id)

                endpoint = (
                    f"/_matrix/client/v3/user/{self.user_id}/account_data/m.direct"
                )
                await self._request("PUT", endpoint, data=direct_data)
            except Exception as e:
                logger.debug(f"Failed to update m.direct: {e}")

        return response

    async def create_room(
        self,
        name: str | None = None,
        topic: str | None = None,
        invite: list[str] | None = None,
        is_public: bool = False,
        preset: str | None = None,
        creation_content: dict[str, Any] | None = None,
        initial_state: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new room

        Args:
            name: Room name
            topic: Room topic
            invite: List of user IDs to invite
            is_public: Whether room is public
            preset: Room preset (private_chat, public_chat, trusted_private_chat)
            creation_content: Room creation_content payload
            initial_state: Room initial_state payload

        Returns:
            Response with room_id
        """
        data: dict[str, Any] = {}

        if name:
            data["name"] = name
        if topic:
            data["topic"] = topic
        if invite:
            data["invite"] = invite
        if preset:
            data["preset"] = preset
        else:
            data["preset"] = "public_chat" if is_public else "private_chat"

        if is_public:
            data["visibility"] = "public"

        if creation_content and isinstance(creation_content, dict):
            data["creation_content"] = creation_content

        if initial_state and isinstance(initial_state, list):
            data["initial_state"] = initial_state

        endpoint = "/_matrix/client/v3/createRoom"
        return await self._request("POST", endpoint, data=data)
