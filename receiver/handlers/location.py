from astrbot.api.message_components import Plain

from ...constants import (
    M_LOCATION,
    MSC1767_TEXT_KEY,
    MSC3488_ASSET_KEY,
    MSC3488_LOCATION_KEY,
)
from ...utils.utils import _extract_text_repr

DEFAULT_ASSET_TYPE = "m.self"
PIN_ASSET_TYPE = "m.pin"


def _extract_location_content(content: dict, event_type: str | None) -> dict:
    for key in (M_LOCATION, MSC3488_LOCATION_KEY):
        location_content = content.get(key)
        if isinstance(location_content, dict):
            return location_content

    if event_type in (M_LOCATION, MSC3488_LOCATION_KEY):
        return content

    return {}


def _extract_location_uri(content: dict, event_type: str | None) -> str:
    geo_uri = content.get("geo_uri")
    if geo_uri:
        return str(geo_uri)

    location_content = _extract_location_content(content, event_type)
    uri = location_content.get("uri") or location_content.get("geo_uri")
    if uri:
        return str(uri)

    return ""


def _extract_location_description(content: dict, event_type: str | None) -> str:
    location_content = _extract_location_content(content, event_type)
    description = location_content.get("description")
    if description:
        return str(description)
    return ""


def _extract_asset_type(content: dict) -> str:
    for key in ("m.asset", MSC3488_ASSET_KEY):
        asset_content = content.get(key)
        if isinstance(asset_content, dict):
            asset_type = asset_content.get("type")
            if asset_type:
                return str(asset_type)
    return DEFAULT_ASSET_TYPE


async def handle_location(receiver, chain, event, event_type: str):
    content = event.content or {}
    resolved_event_type = getattr(event, "event_type", None) or event_type
    geo_uri = _extract_location_uri(content, resolved_event_type)
    body = (
        getattr(event, "body", "")
        or content.get("body", "")
        or _extract_text_repr(content.get("m.text"))
        or _extract_text_repr(content.get(MSC1767_TEXT_KEY))
        or _extract_location_description(content, resolved_event_type)
    )
    prefix = (
        "[位置标记]" if _extract_asset_type(content) == PIN_ASSET_TYPE else "[位置]"
    )
    if body and geo_uri:
        text = f"{prefix} {body} {geo_uri}"
    elif body:
        text = f"{prefix} {body}"
    elif geo_uri:
        text = f"{prefix} {geo_uri}"
    else:
        text = prefix
    chain.chain.append(Plain(text))
