"""Matrix 消息发送组件 - 房间消息/读取扩展 mixin"""

from typing import Any

from ..constants import (
    M_BEACON,
    M_BEACON_INFO,
    M_PROFILE_KEY,
    M_ROOM_MESSAGE,
    MATRIX_HTML_FORMAT,
    MSC1767_TEXT_KEY,
    MSC3488_ASSET_KEY,
    MSC3488_TS_KEY,
    CONTENT_KEY_RELATES_TO,
    MSC4144_PROFILE_KEY,
    REL_TYPE_REFERENCE,
)


class SenderRoomMessagingMixin:
    async def get_mutual_rooms(
        self,
        user_id: str,
        *,
        from_token: str | None = None,
    ) -> dict:
        """Get one Matrix v1.19 mutual-room page for ``user_id``."""
        return await self.client.get_mutual_rooms(
            user_id=user_id,
            from_token=from_token,
        )

    async def get_key_backup_preference(self) -> bool | None:
        """Read the account-wide Matrix v1.19 key-backup preference."""
        return await self.client.get_key_backup_preference()

    async def set_key_backup_preference(self, enabled: bool) -> dict:
        """Set the account-wide Matrix v1.19 key-backup preference."""
        return await self.client.set_key_backup_preference(enabled)

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

    async def send_with_per_message_profile(
        self,
        room_id: str,
        body: str,
        *,
        displayname: str | None = None,
        avatar_url: str | None = None,
        msgtype: str | None = None,
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
            msgtype: Explicit message type. When omitted, follows the sender's
                configured notice mode and otherwise defaults to ``m.text``.
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

        resolved_msgtype = msgtype or ("m.notice" if self.use_notice else "m.text")
        content: dict[str, Any] = {
            "msgtype": resolved_msgtype,
            "body": body,
            MSC4144_PROFILE_KEY: dict(profile),
        }
        if stable:
            content[M_PROFILE_KEY] = dict(profile)
        if formatted_body:
            content["format"] = MATRIX_HTML_FORMAT
            content["formatted_body"] = formatted_body

        return await self.send_custom_message(
            room_id,
            M_ROOM_MESSAGE,
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
            CONTENT_KEY_RELATES_TO: {
                "rel_type": REL_TYPE_REFERENCE,
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
