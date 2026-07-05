"""
Matrix 消息发送组件
"""

from typing import Any

from astrbot.api.event import MessageChain
from astrbot.api.message_components import Record, Video

from ..constants import (
    M_BEACON,
    M_BEACON_INFO,
    M_PROFILE_KEY,
    MSC1767_TEXT_KEY,
    MSC3488_ASSET_KEY,
    MSC3488_TS_KEY,
    MSC4144_PROFILE_KEY,
)

# Update import: markdown_utils is now in ..utils.markdown_utils


class MatrixSender:
    def __init__(self, client, e2ee_manager=None):
        self.client = client
        self.e2ee_manager = e2ee_manager

    async def send_message(
        self,
        room_id: str,
        message_chain: MessageChain,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """
        Send a message to a room
        """
        from ..matrix_event import MatrixPlatformEvent

        return await MatrixPlatformEvent.send_with_client(
            self.client,
            message_chain,
            room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            e2ee_manager=self.e2ee_manager,
            use_notice=use_notice,
        )

    async def send_video(
        self,
        room_id: str,
        video: str,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """Send a video to a room (file path or http/https URL)."""
        if video.startswith("http://") or video.startswith("https://"):
            segment = Video.fromURL(video)
        else:
            segment = Video.fromFileSystem(video)
        return await self.send_message(
            room_id,
            MessageChain([segment]),
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            use_notice=use_notice,
        )

    async def send_audio(
        self,
        room_id: str,
        audio: str,
        reply_to: str = None,
        thread_root: str = None,
        use_thread: bool = False,
        use_notice: bool = False,
    ) -> int:
        """Send an audio clip to a room (file path or http/https URL)."""
        if audio.startswith("http://") or audio.startswith("https://"):
            segment = Record.fromURL(audio)
        else:
            segment = Record.fromFileSystem(audio)
        return await self.send_message(
            room_id,
            MessageChain([segment]),
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            use_notice=use_notice,
        )

    async def send_custom_message(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
    ) -> dict | None:
        """
        Send a custom Matrix room event.

        Args:
            room_id: Room ID
            event_type: Matrix event type, e.g. `m.room.message` or `org.example.custom`
            content: Event content dictionary
            reply_to: Optional event ID to reply to
            thread_root: Optional thread root event ID
            use_thread: Whether to send as threaded event

        Returns:
            Matrix API response (usually containing event_id), or None on failure
        """
        if not event_type or not isinstance(event_type, str):
            raise ValueError("event_type must be a non-empty string")
        if not isinstance(content, dict):
            raise ValueError("content must be a dict")

        from .handlers.common import send_content

        is_encrypted_room = False
        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

        return await send_content(
            client=self.client,
            content=dict(content),
            room_id=room_id,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
            is_encrypted_room=is_encrypted_room,
            e2ee_manager=self.e2ee_manager,
            msg_type=event_type,
        )

    async def send_custom_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
    ) -> dict | None:
        """Alias of send_custom_message."""
        return await self.send_custom_message(
            room_id=room_id,
            event_type=event_type,
            content=content,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
        )

    async def send_reaction(self, room_id: str, event_id: str, emoji: str) -> dict:
        """Send a reaction to a message in a room."""
        return await self.client.send_reaction(room_id, event_id, emoji)

    async def send_receipt(
        self,
        room_id: str,
        event_id: str,
        receipt_type: str = "m.read",
        thread_id: str | None = None,
    ) -> dict:
        """Send a read/private-read receipt for a room event."""
        if receipt_type == "m.read.private":
            return await self.client.send_read_receipt_private(
                room_id, event_id, thread_id=thread_id
            )
        return await self.client.send_read_receipt(
            room_id, event_id, thread_id=thread_id
        )

    async def set_typing(
        self, room_id: str, typing: bool, timeout_ms: int = 30000
    ) -> dict:
        """Update typing indicator state."""
        return await self.client.set_typing(
            room_id=room_id, typing=typing, timeout=timeout_ms
        )

    async def send_poll(
        self,
        room_id: str,
        question: str,
        answers: list[str],
        max_selections: int = 1,
        kind: str = "m.disclosed",
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        event_type: str = "m.poll.start",
        poll_key: str = "m.poll",
        fallback_text: str | None = None,
        fallback_html: str | None = None,
    ) -> dict | None:
        """Send a poll to a room."""
        from ..sender.handlers import send_poll

        is_encrypted_room = False
        if self.e2ee_manager:
            try:
                is_encrypted_room = await self.client.is_room_encrypted(room_id)
            except Exception:
                is_encrypted_room = False

        return await send_poll(
            self.client,
            room_id,
            question,
            answers,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            self.e2ee_manager,
            max_selections=max_selections,
            kind=kind,
            event_type=event_type,
            poll_key=poll_key,
            fallback_text=fallback_text,
            fallback_html=fallback_html,
        )

    async def send_poll_response(
        self,
        room_id: str,
        poll_start_event_id: str,
        answer_ids: list[str],
        event_type: str = "m.poll.response",
        poll_key: str = "m.poll",
    ) -> dict | None:
        """Send a response to an existing poll.

        Args:
            room_id: Room ID
            poll_start_event_id: The event ID of the poll start event
            answer_ids: List of answer IDs to vote for.
                Stable polls use IDs like ["answer_1"], while MSC3381 polls
                usually use ["1"].
            event_type: Event type to use (m.poll.response or org.matrix.msc3381.poll.response)
            poll_key: Poll key to use (m.poll or org.matrix.msc3381.poll.response)

        Returns:
            The response from the server, or None on failure
        """
        from ..sender.handlers import send_poll_response

        return await send_poll_response(
            self.client,
            room_id,
            poll_start_event_id,
            answer_ids,
            event_type=event_type,
            poll_key=poll_key,
        )

    async def delete_message(
        self,
        room_id: str,
        event_id: str,
        reason: str | None = None,
        txn_id: str | None = None,
    ) -> dict:
        """Delete (redact) a message in a room."""
        return await self.client.redact_event(
            room_id, event_id, reason=reason, txn_id=txn_id
        )

    async def report_message(
        self,
        room_id: str,
        event_id: str,
        *,
        score: int = -100,
        reason: str | None = None,
    ) -> dict:
        """Report an abusive Matrix event."""
        return await self.client.report_event(
            room_id=room_id,
            event_id=event_id,
            score=score,
            reason=reason,
        )

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

    async def get_message_relations(
        self,
        room_id: str,
        event_id: str,
        rel_type: str,
        *,
        event_type: str | None = None,
        from_token: str | None = None,
        to_token: str | None = None,
        limit: int | None = None,
    ) -> dict:
        """Get Matrix relations for an event, such as reactions or edits."""
        return await self.client.get_event_relations(
            room_id=room_id,
            event_id=event_id,
            rel_type=rel_type,
            event_type=event_type,
            from_token=from_token,
            to_token=to_token,
            limit=limit,
        )

    async def set_read_markers(
        self,
        room_id: str,
        *,
        fully_read: str | None = None,
        read: str | None = None,
        allow_backward: bool = False,
    ) -> dict:
        """Set room read markers.

        ``allow_backward`` (MSC4446) 允许把 ``m.fully_read`` 回移到更早的事件。
        """
        return await self.client.send_read_markers(
            room_id=room_id,
            fully_read=fully_read,
            read=read,
            allow_backward=allow_backward,
        )

    async def set_fully_read_marker(
        self,
        room_id: str,
        event_id: str,
        *,
        allow_backward: bool = False,
    ) -> dict:
        """把 fully read 标记移到指定事件（走 receipt 端点，MSC4446 aware）。"""
        return await self.client.send_fully_read_receipt(
            room_id=room_id,
            event_id=event_id,
            allow_backward=allow_backward,
        )

    async def create_room(
        self,
        *,
        name: str | None = None,
        topic: str | None = None,
        invite: list[str] | None = None,
        is_public: bool = False,
        preset: str | None = None,
        creation_content: dict[str, Any] | None = None,
        initial_state: list[dict[str, Any]] | None = None,
    ) -> dict:
        """Create a Matrix room."""
        return await self.client.create_room(
            name=name,
            topic=topic,
            invite=invite,
            is_public=is_public,
            preset=preset,
            creation_content=creation_content,
            initial_state=initial_state,
        )

    async def create_dm_room(
        self,
        user_id: str,
        name: str | None = None,
    ) -> dict:
        """Create a Matrix direct-message room and update m.direct when possible."""
        return await self.client.create_dm_room(user_id=user_id, name=name)

    async def get_user_room(self, user_id: str) -> str | None:
        """Find an existing direct-message room for a Matrix user."""
        return await self.client.get_user_room(user_id)

    async def join_room(self, room_id_or_alias: str) -> dict:
        """Join a Matrix room by room ID or alias."""
        return await self.client.join_room(room_id_or_alias)

    async def leave_room(self, room_id: str) -> dict:
        """Leave a Matrix room."""
        return await self.client.leave_room(room_id)

    async def forget_room(self, room_id: str) -> dict:
        """Forget a Matrix room after leaving it."""
        return await self.client.forget_room(room_id)

    async def get_joined_rooms(self) -> list[str]:
        """Get room IDs joined by the current Matrix account."""
        return await self.client.get_joined_rooms()

    async def get_room_members(self, room_id: str) -> dict:
        """Get Matrix room member events."""
        return await self.client.get_room_members(room_id)

    async def get_room_messages(
        self,
        room_id: str,
        *,
        from_token: str | None = None,
        to_token: str | None = None,
        direction: str = "b",
        limit: int = 10,
    ) -> dict:
        """Paginate Matrix room messages."""
        return await self.client.room_messages(
            room_id=room_id,
            from_token=from_token,
            to_token=to_token,
            direction=direction,
            limit=limit,
        )

    async def get_room_state(self, room_id: str) -> list[dict[str, Any]]:
        """Get full Matrix room state."""
        return await self.client.get_room_state(room_id)

    async def get_room_state_event(
        self,
        room_id: str,
        event_type: str,
        state_key: str = "",
    ) -> dict:
        """Get a specific Matrix room state event content."""
        return await self.client.get_room_state_event(
            room_id=room_id,
            event_type=event_type,
            state_key=state_key,
        )

    async def set_room_state_event(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        state_key: str = "",
    ) -> dict:
        """Set a generic Matrix room state event."""
        return await self.client.set_room_state_event(
            room_id=room_id,
            event_type=event_type,
            content=content,
            state_key=state_key,
        )

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
        return await self.client.set_room_presence_sharing(
            room_id=room_id, hint=hint
        )

    async def get_room_presence_sharing(self, room_id: str) -> str | None:
        """读取房间 presence sharing hint（MSC4495），缺失视为 'forbid'。"""
        return await self.client.get_room_presence_sharing(room_id=room_id)

    async def get_event(self, room_id: str, event_id: str) -> dict:
        """Fetch one Matrix event from a room."""
        return await self.client.get_event(room_id=room_id, event_id=event_id)

    async def search_messages(
        self,
        search_term: str,
        *,
        keys: list[str] | None = None,
        filter: dict[str, Any] | None = None,
        order_by: str = "recent",
        event_context: dict[str, Any] | None = None,
    ) -> dict:
        """Search Matrix room events by content."""
        return await self.client.search(
            search_term=search_term,
            keys=keys,
            filter=filter,
            order_by=order_by,
            event_context=event_context,
        )

    async def upgrade_room(self, room_id: str, new_version: str) -> dict:
        """Upgrade a Matrix room to a new room version."""
        return await self.client.upgrade_room(room_id=room_id, new_version=new_version)

    async def send_call_decline(
        self,
        room_id: str,
        notification_event_id: str,
        *,
        reason: str | None = None,
    ) -> dict:
        """发送 MatrixRTC 通话拒接事件（MSC4310）。

        以 ``m.reference`` 关联指定的 ``m.rtc.notification`` 事件。
        """
        return await self.client.send_call_decline(
            room_id=room_id,
            notification_event_id=notification_event_id,
            reason=reason,
        )

    async def knock_room(
        self,
        room_id_or_alias: str,
        reason: str | None = None,
    ) -> dict:
        """Knock on a Matrix room that uses knock join rules."""
        return await self.client.knock_room(
            room_id_or_alias=room_id_or_alias,
            reason=reason,
        )

    async def accept_knock(
        self,
        room_id: str,
        user_id: str,
        reason: str | None = None,
    ) -> dict:
        """Accept a Matrix knock request by inviting the user."""
        return await self.client.accept_knock(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def reject_knock(
        self,
        room_id: str,
        user_id: str,
        reason: str | None = None,
    ) -> dict:
        """Reject a Matrix knock request by kicking the knocking user."""
        return await self.client.reject_knock(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def get_room_hierarchy(
        self,
        room_id: str,
        *,
        limit: int | None = None,
        from_token: str | None = None,
    ) -> dict:
        """Get Matrix space/room hierarchy."""
        return await self.client.get_room_hierarchy(
            room_id=room_id,
            limit=limit,
            from_token=from_token,
        )

    async def invite_user(self, room_id: str, user_id: str) -> dict:
        """Invite a Matrix user to a room."""
        return await self.client.invite_user(room_id=room_id, user_id=user_id)

    async def kick_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict:
        """Kick a Matrix user from a room."""
        return await self.client.kick_user(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def ban_user(
        self, room_id: str, user_id: str, reason: str | None = None
    ) -> dict:
        """Ban a Matrix user from a room."""
        return await self.client.ban_user(
            room_id=room_id,
            user_id=user_id,
            reason=reason,
        )

    async def unban_user(self, room_id: str, user_id: str) -> dict:
        """Unban a Matrix user from a room."""
        return await self.client.unban_user(room_id=room_id, user_id=user_id)

    async def set_user_power_level(
        self, room_id: str, user_id: str, power_level: int
    ) -> dict:
        """Set a user's room power level."""
        return await self.client.set_user_power_level(
            room_id=room_id,
            user_id=user_id,
            power_level=power_level,
        )

    async def promote_to_moderator(self, room_id: str, user_id: str) -> dict:
        """Promote a Matrix user to moderator (power level 50)."""
        return await self.client.promote_to_moderator(
            room_id=room_id,
            user_id=user_id,
        )

    async def promote_to_admin(self, room_id: str, user_id: str) -> dict:
        """Promote a Matrix user to admin (power level 100)."""
        return await self.client.promote_to_admin(room_id=room_id, user_id=user_id)

    async def demote_user(self, room_id: str, user_id: str) -> dict:
        """Demote a Matrix user to the room default power level."""
        return await self.client.demote_user(room_id=room_id, user_id=user_id)

    async def get_room_admins(self, room_id: str) -> list[str]:
        """Get room admins (power level >= 100)."""
        return await self.client.get_room_admins(room_id)

    async def get_room_moderators(self, room_id: str) -> list[str]:
        """Get room moderators (power level >= 50)."""
        return await self.client.get_room_moderators(room_id)

    async def set_room_name(self, room_id: str, name: str) -> dict:
        """Set the Matrix room name."""
        return await self.client.set_room_name(room_id=room_id, name=name)

    async def set_room_topic(self, room_id: str, topic: str) -> dict:
        """Set the Matrix room topic."""
        return await self.client.set_room_topic(room_id=room_id, topic=topic)

    async def set_room_avatar(self, room_id: str, avatar_url: str) -> dict:
        """Set the Matrix room avatar MXC URL."""
        return await self.client.set_room_avatar(
            room_id=room_id,
            avatar_url=avatar_url,
        )

    async def set_room_join_rules(self, room_id: str, join_rule: str) -> dict:
        """Set Matrix room join rules."""
        return await self.client.set_room_join_rules(
            room_id=room_id,
            join_rule=join_rule,
        )

    async def set_room_history_visibility(
        self, room_id: str, history_visibility: str
    ) -> dict:
        """Set Matrix room history visibility."""
        return await self.client.set_room_history_visibility(
            room_id=room_id,
            history_visibility=history_visibility,
        )

    async def set_room_guest_access(self, room_id: str, guest_access: str) -> dict:
        """Set Matrix room guest access."""
        return await self.client.set_room_guest_access(
            room_id=room_id,
            guest_access=guest_access,
        )

    async def set_room_canonical_alias(
        self,
        room_id: str,
        alias: str | None,
        alt_aliases: list[str] | None = None,
    ) -> dict:
        """Set or clear the Matrix room canonical alias."""
        return await self.client.set_room_canonical_alias(
            room_id=room_id,
            alias=alias,
            alt_aliases=alt_aliases,
        )

    async def create_room_alias(self, room_alias: str, room_id: str) -> dict:
        """Create or update a Matrix room alias."""
        return await self.client.create_room_alias(
            room_alias=room_alias,
            room_id=room_id,
        )

    async def delete_room_alias(self, room_alias: str) -> dict:
        """Delete a Matrix room alias."""
        return await self.client.delete_room_alias(room_alias)

    async def get_room_alias(self, room_alias: str) -> dict:
        """Resolve a Matrix room alias to its room ID and servers."""
        return await self.client.get_room_alias(room_alias)

    async def list_public_rooms(
        self,
        *,
        server: str | None = None,
        limit: int | None = None,
        since: str | None = None,
        filter: dict[str, Any] | None = None,
    ) -> dict:
        """List Matrix public rooms, optionally on another server."""
        return await self.client.list_public_rooms(
            server=server,
            limit=limit,
            since=since,
            filter=filter,
        )

    async def get_room_visibility(self, room_id: str) -> dict:
        """Get room visibility in the public directory."""
        return await self.client.get_room_visibility(room_id)

    async def set_room_visibility(self, room_id: str, visibility: str) -> dict:
        """Set room visibility in the public directory."""
        return await self.client.set_room_visibility(
            room_id=room_id,
            visibility=visibility,
        )

    async def get_room_aliases(self, room_id: str) -> dict:
        """Get aliases associated with a Matrix room."""
        return await self.client.get_room_aliases(room_id)

    async def get_pinned_messages(self, room_id: str) -> list[str]:
        """Get pinned Matrix event IDs in a room."""
        return await self.client.get_room_pinned_events(room_id)

    async def set_pinned_messages(
        self, room_id: str, event_ids
    ) -> dict:
        """Replace pinned Matrix event IDs in a room."""
        return await self.client.set_room_pinned_events(room_id, event_ids)

    async def pin_message(
        self, room_id: str, event_id: str, *, prepend: bool = False
    ) -> dict:
        """Pin a Matrix event in a room."""
        return await self.client.pin_room_event(
            room_id=room_id,
            event_id=event_id,
            prepend=prepend,
        )

    async def unpin_message(self, room_id: str, event_id: str) -> dict:
        """Unpin a Matrix event in a room."""
        return await self.client.unpin_room_event(room_id=room_id, event_id=event_id)

    async def send_with_per_message_profile(
        self,
        room_id: str,
        body: str,
        *,
        displayname: str | None = None,
        avatar_url: str | None = None,
        msgtype: str = "m.text",
        formatted_body: str | None = None,
        reply_to: str | None = None,
        thread_root: str | None = None,
        use_thread: bool = False,
        stable: bool = True,
    ) -> dict | None:
        """
        Send a message with a per-message profile override (MSC4144).

        Bridges and bots often need to render messages under a different
        identity than the sending Matrix user. MSC4144 lets the sender attach
        an alternate ``displayname``/``avatar_url`` to a single event without
        touching the underlying profile.

        Args:
            room_id: Target room ID
            body: Plain-text body
            displayname: Display name to attach to this message
            avatar_url: ``mxc://`` avatar URL to attach to this message
            msgtype: Message type, defaults to ``m.text``
            formatted_body: Optional HTML formatted body
            stable: Also include the stable ``m.per_message_profile`` key
                alongside the unstable ``com.beeper.per_message_profile`` key
        """
        if not displayname and not avatar_url:
            raise ValueError(
                "at least one of displayname/avatar_url is required for per-message profile"
            )
        profile: dict[str, Any] = {}
        if displayname:
            profile["displayname"] = displayname
        if avatar_url:
            profile["avatar_url"] = avatar_url

        content: dict[str, Any] = {
            "msgtype": msgtype,
            "body": body,
            MSC4144_PROFILE_KEY: dict(profile),
        }
        if stable:
            content[M_PROFILE_KEY] = dict(profile)
        if formatted_body:
            content["format"] = "org.matrix.custom.html"
            content["formatted_body"] = formatted_body

        return await self.send_custom_message(
            room_id,
            "m.room.message",
            content,
            reply_to=reply_to,
            thread_root=thread_root,
            use_thread=use_thread,
        )

    async def send_live_location_beacon_info(
        self,
        room_id: str,
        *,
        description: str | None = None,
        timeout_ms: int = 3600_000,
        live: bool = True,
        asset_type: str = "m.self",
    ) -> dict | None:
        """
        Publish a live-location ``m.beacon_info`` state event (MSC3489).

        The state key MUST be the sender's user ID. Once published, the sender
        can call :meth:`send_live_location_beacon` repeatedly to publish
        ``m.beacon`` events that update the location.
        """
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive for live location")
        user_id = getattr(self.client, "user_id", None)
        if not user_id:
            raise RuntimeError("client.user_id is required for beacon_info")

        ts_ms = int(self._now_ms())
        content: dict[str, Any] = {
            "live": bool(live),
            "timeout": int(timeout_ms),
            "m.ts": ts_ms,
            MSC3488_TS_KEY: ts_ms,
            MSC3488_ASSET_KEY: {"type": asset_type},
            "m.asset": {"type": asset_type},
        }
        if description:
            content["description"] = description

        return await self.client.set_room_state_event(
            room_id=room_id,
            event_type=M_BEACON_INFO,
            content=content,
            state_key=user_id,
        )

    async def send_live_location_beacon(
        self,
        room_id: str,
        beacon_info_event_id: str,
        latitude: float,
        longitude: float,
        *,
        accuracy_m: float | None = None,
        description: str | None = None,
    ) -> dict | None:
        """
        Publish a live-location ``m.beacon`` update (MSC3489).

        Args:
            beacon_info_event_id: The event ID of the ``m.beacon_info`` state event.
            latitude / longitude: Coordinates of the location update.
            accuracy_m: Optional horizontal accuracy in meters.
            description: Optional human-readable description.
        """
        if not beacon_info_event_id:
            raise ValueError("beacon_info_event_id is required")

        geo_uri = f"geo:{latitude},{longitude}"
        if accuracy_m and accuracy_m > 0:
            geo_uri += f";u={accuracy_m}"
        location_payload: dict[str, Any] = {"uri": geo_uri}
        if description:
            location_payload["description"] = description

        ts_ms = int(self._now_ms())
        content: dict[str, Any] = {
            "m.location": location_payload,
            "org.matrix.msc3488.location": dict(location_payload),
            "m.ts": ts_ms,
            MSC3488_TS_KEY: ts_ms,
            "m.relates_to": {
                "rel_type": "m.reference",
                "event_id": beacon_info_event_id,
            },
            MSC1767_TEXT_KEY: description or geo_uri,
        }

        return await self.client.send_room_event(
            room_id=room_id,
            event_type=M_BEACON,
            content=content,
            txn_id=None,
        )

    async def mark_room_unread(
        self, room_id: str, unread: bool = True
    ) -> dict:
        """Mark a room as (un)read for this account (MSC2867)."""
        return await self.client.set_room_marked_unread(room_id, unread)

    async def send_delayed_message(
        self,
        room_id: str,
        event_type: str,
        content: dict[str, Any],
        delay_ms: int,
        parent_delay_id: str | None = None,
    ) -> dict:
        """Schedule a delayed Matrix event (MSC4140)."""
        return await self.client.send_delayed_room_event(
            room_id=room_id,
            event_type=event_type,
            content=content,
            delay_ms=delay_ms,
            parent_delay_id=parent_delay_id,
        )

    async def cancel_delayed_message(self, delay_id: str) -> dict:
        """Cancel a previously scheduled delayed event (MSC4140)."""
        return await self.client.cancel_delayed_event(delay_id)

    async def fire_delayed_message(self, delay_id: str) -> dict:
        """Immediately fire a pending delayed event (MSC4140)."""
        return await self.client.fire_delayed_event(delay_id)

    async def restart_delayed_message(self, delay_id: str) -> dict:
        """Reset the timeout on a pending delayed event (MSC4140)."""
        return await self.client.restart_delayed_event(delay_id)

    async def list_delayed_messages(
        self, from_token: str | None = None, limit: int | None = None
    ) -> dict:
        """List currently pending delayed events (MSC4140)."""
        return await self.client.list_delayed_events(
            from_token=from_token, limit=limit
        )

    @staticmethod
    def _now_ms() -> int:
        import time

        return int(time.time() * 1000)
