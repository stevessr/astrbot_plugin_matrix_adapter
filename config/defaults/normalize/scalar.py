"""Scalar configuration normalization helpers."""

from .warn import _warn_config_coercion


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
