"""Per-message profile sender extension."""

from typing import Any

from ...constants import (
    M_PROFILE_KEY,
    M_ROOM_MESSAGE,
    MATRIX_HTML_FORMAT,
    MSC4144_PROFILE_KEY,
)


class SenderProfileMixin:
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


__all__ = ["SenderProfileMixin"]
