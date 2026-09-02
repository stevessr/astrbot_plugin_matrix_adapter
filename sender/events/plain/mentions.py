"""Reply mention merging for plain text sends."""


def _merge_reply_mentions(
    content: dict, client, original_message_info: dict | None
) -> None:
    """Merge only the new message's mentions and the replied-to sender.

    Matrix v1.16 / MSC4142 explicitly stops propagating users mentioned by the
    replied-to event through the reply chain. The replied-to sender is still
    mentioned by default, while mentions already present on the new outbound
    content are preserved.
    """
    if not isinstance(original_message_info, dict):
        return

    existing_mentions = content.get("m.mentions")
    existing_user_ids = []
    room_mention = False
    if isinstance(existing_mentions, dict):
        existing_user_ids = list(existing_mentions.get("user_ids") or [])
        room_mention = bool(existing_mentions.get("room"))

    current_user_id = getattr(client, "user_id", None)
    merged_user_ids: list[str] = []

    def _add_user_id(user_id: str | None) -> None:
        if not user_id or not isinstance(user_id, str):
            return
        if current_user_id and user_id == current_user_id:
            return
        if user_id not in merged_user_ids:
            merged_user_ids.append(user_id)

    # MSC4142: include the sender being replied to, but intentionally do not
    # copy original_message_info["mentions"] from the previous event.
    _add_user_id(original_message_info.get("sender"))

    for user_id in existing_user_ids:
        _add_user_id(user_id)

    mentions: dict[str, object] = {}
    if merged_user_ids:
        mentions["user_ids"] = merged_user_ids
    if room_mention:
        mentions["room"] = True
    content["m.mentions"] = mentions


__all__ = ["_merge_reply_mentions"]
