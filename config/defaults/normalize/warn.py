"""Configuration coercion warning helper."""

from astrbot.api import logger


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
