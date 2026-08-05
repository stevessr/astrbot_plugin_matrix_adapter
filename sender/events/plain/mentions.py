"""Reply mention merging for plain text sends."""


def _merge_reply_mentions(
    content: dict, client, original_message_info: dict | None
) -> None:
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

    _add_user_id(original_message_info.get("sender"))

    original_mentions = original_message_info.get("mentions")
    if isinstance(original_mentions, dict):
        for user_id in original_mentions.get("user_ids") or []:
            _add_user_id(user_id)

    for user_id in existing_user_ids:
        _add_user_id(user_id)

    if merged_user_ids or room_mention:
        mentions: dict[str, object] = {}
        if merged_user_ids:
            mentions["user_ids"] = merged_user_ids
        if room_mention:
            mentions["room"] = True
        content["m.mentions"] = mentions


__all__ = ["_merge_reply_mentions"]
