"""Normalization helpers for plugin configuration values."""

from astrbot.api import logger

from ...utils.utils import parse_bool


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


def _warn_config_coercion(
    config_key: str,
    raw_value,
    normalized_value,
    reason: str,
) -> None:
    logger.warning(
        f"Config {config_key} coerced: raw={raw_value!r}, "
        f"normalized={normalized_value!r} ({reason})"
    )


def _normalize_pgsql_schema(value) -> str:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            return normalized
    return "public"


def _normalize_pgsql_table_prefix(value) -> str:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            return normalized
    return "matrix_store"


_normalize_bool = parse_bool


def _normalize_non_negative_int(
    value,
    default: int = 0,
    *,
    min_value: int = 0,
    config_key: str | None = None,
) -> int:
    if value is None:
        return default
    try:
        normalized = int(value)
    except Exception:
        if config_key:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=default,
                reason="invalid integer, fallback to default",
            )
        return default
    if normalized < min_value:
        if config_key:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=min_value,
                reason=f"value below minimum {min_value}",
            )
        return min_value
    return normalized


def _normalize_token_list(
    value,
    default: tuple[str, ...],
    *,
    extension_mode: bool = False,
    config_key: str | None = None,
) -> tuple[str, ...]:
    raw_tokens: list[str] = []
    if isinstance(value, str):
        raw_tokens = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw_tokens = [str(item) for item in value if isinstance(item, str)]
    else:
        if value is not None and config_key:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=default,
                reason="invalid list type, fallback to default",
            )
        return default

    normalized_tokens: list[str] = []
    changed = False
    for token in raw_tokens:
        original = token
        normalized = token.strip().lower()
        if not normalized:
            changed = True
            continue
        if extension_mode and normalized != "*" and not normalized.startswith("."):
            normalized = f".{normalized}"
            changed = True
        if normalized != original:
            changed = True
        if normalized not in normalized_tokens:
            normalized_tokens.append(normalized)
        else:
            changed = True

    if not normalized_tokens:
        if config_key and value is not None:
            _warn_config_coercion(
                config_key=config_key,
                raw_value=value,
                normalized_value=default,
                reason="no valid tokens, fallback to default",
            )
        return default

    result = tuple(normalized_tokens)
    if changed and config_key:
        _warn_config_coercion(
            config_key=config_key,
            raw_value=value,
            normalized_value=result,
            reason="normalized tokens",
        )
    return result
