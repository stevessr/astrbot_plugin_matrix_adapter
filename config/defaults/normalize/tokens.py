"""Token-list configuration normalization."""

from .warn import _warn_config_coercion


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
