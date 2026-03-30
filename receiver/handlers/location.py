from astrbot.api.message_components import Plain


DEFAULT_ASSET_TYPE = "m.self"
PIN_ASSET_TYPE = "m.pin"
STABLE_LOCATION_EVENT_TYPE = "m.location"
UNSTABLE_LOCATION_EVENT_TYPE = "org.matrix.msc3488.location"
STABLE_LOCATION_KEY = "m.location"
UNSTABLE_LOCATION_KEY = "org.matrix.msc3488.location"
STABLE_ASSET_KEY = "m.asset"
UNSTABLE_ASSET_KEY = "org.matrix.msc3488.asset"


def _extract_text_repr(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("body") or value.get("text") or "")
    if isinstance(value, list):
        for item in value:
            text = _extract_text_repr(item)
            if text:
                return text
    return ""


def _extract_location_content(content: dict, event_type: str | None) -> dict:
    for key in (STABLE_LOCATION_KEY, UNSTABLE_LOCATION_KEY):
        location_content = content.get(key)
        if isinstance(location_content, dict):
            return location_content

    if event_type in (STABLE_LOCATION_EVENT_TYPE, UNSTABLE_LOCATION_EVENT_TYPE):
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
    for key in (STABLE_ASSET_KEY, UNSTABLE_ASSET_KEY):
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
        or _extract_text_repr(content.get("org.matrix.msc1767.text"))
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
