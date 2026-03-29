"""
Helpers for Matrix auth callbacks over AstrBot unified webhooks.
"""

from astrbot.api import logger


def build_unified_webhook_url(webhook_uuid: str) -> str:
    """Build the absolute AstrBot unified webhook URL for a platform."""
    normalized_uuid = str(webhook_uuid or "").strip()
    if not normalized_uuid:
        raise ValueError("webhook_uuid is required")

    callback_base = ""
    dashboard_port = 6185
    ssl_enabled = False

    try:
        from astrbot.core.utils.webhook_utils import (
            _get_callback_api_base,
            _get_dashboard_port,
            _is_dashboard_ssl_enabled,
        )

        callback_base = str(_get_callback_api_base() or "").strip().rstrip("/")
        dashboard_port = int(_get_dashboard_port() or 6185)
        ssl_enabled = bool(_is_dashboard_ssl_enabled())
    except Exception as e:
        logger.debug(f"读取 AstrBot 统一 Webhook 配置失败，回退本地默认地址：{e}")

    scheme = "https" if ssl_enabled else "http"
    if callback_base:
        if not callback_base.startswith(("http://", "https://")):
            callback_base = f"{scheme}://{callback_base.lstrip('/')}"
    else:
        callback_base = f"{scheme}://127.0.0.1:{dashboard_port}"

    return f"{callback_base.rstrip('/')}/api/platform/webhook/{normalized_uuid}"
