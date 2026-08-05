"""Message-type configuration normalization."""


def _normalize_message_type(value, legacy_value) -> str:
    """归一化消息类型配置"""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"auto", "private", "group", "stalk"}:
            return normalized
    if isinstance(value, bool):
        return "private" if value else "auto"
    if isinstance(legacy_value, bool):
        return "private" if legacy_value else "auto"
    return "auto"
