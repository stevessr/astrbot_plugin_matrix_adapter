from astrbot.api.message_components import Location

from ...constants import (
    M_LOCATION,
    MSC3488_ASSET_KEY,
    MSC3488_LOCATION_KEY,
)
from .common import send_content

DEFAULT_ASSET_TYPE = "m.self"


def _build_text_repr(text: str) -> list[dict[str, str]]:
    text = str(text or "").strip()
    return [{"body": text}] if text else []


def _build_location_repr(uri: str, description: str) -> dict[str, str]:
    location_repr = {"uri": uri}
    description = str(description or "").strip()
    if description and description != uri:
        location_repr["description"] = description
    return location_repr


async def send_location(
    client,
    segment: Location,
    room_id: str,
    reply_to: str | None,
    thread_root: str | None,
    use_thread: bool,
    is_encrypted_room: bool,
    e2ee_manager,
    thread_is_falling_back: bool | None = None,
) -> None:
    geo_uri = f"geo:{segment.lat},{segment.lon}"
    body = segment.title or segment.content or geo_uri
    location_repr = _build_location_repr(geo_uri, body)
    asset_repr = {"type": DEFAULT_ASSET_TYPE}
    content = {
        "msgtype": "m.location",
        "body": body,
        "geo_uri": geo_uri,
        M_LOCATION: location_repr,
        "m.asset": dict(asset_repr),
        MSC3488_LOCATION_KEY: dict(location_repr),
        MSC3488_ASSET_KEY: dict(asset_repr),
    }
    text_repr = _build_text_repr(body)
    if text_repr:
        content["m.text"] = text_repr

    await send_content(
        client,
        content,
        room_id,
        reply_to,
        thread_root,
        use_thread,
        is_encrypted_room,
        e2ee_manager,
        thread_is_falling_back=thread_is_falling_back,
    )
