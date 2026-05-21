"""Handlers for MSC3489 live-location beacons.

`m.beacon_info` is a state event that opens a live-location session, and
`m.beacon` is a regular room event carrying a single location update that
references the beacon_info via ``m.relates_to``.
"""

from astrbot.api.message_components import Plain

from ...constants import (
    M_BEACON,
    M_BEACON_INFO,
    MSC1767_TEXT_KEY,
    MSC3488_LOCATION_KEY,
)


def _extract_text_repr(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("body") or value.get("text") or "")
    if isinstance(value, list):
        for item in value:
            extracted = _extract_text_repr(item)
            if extracted:
                return extracted
    return ""


def _resolve_location_payload(content: dict) -> dict:
    for key in ("m.location", MSC3488_LOCATION_KEY):
        payload = content.get(key)
        if isinstance(payload, dict):
            return payload
    return {}


async def handle_beacon_info(receiver, chain, event, _: str):
    """Render ``m.beacon_info`` state changes for user visibility."""
    content = event.content or {}
    live = bool(content.get("live"))
    description = content.get("description") or ""
    timeout = content.get("timeout")
    if live:
        suffix = f"（{description}）" if description else ""
        if isinstance(timeout, int) and timeout > 0:
            chain.chain.append(
                Plain(f"[实时位置开启{suffix} timeout={timeout}ms]")
            )
        else:
            chain.chain.append(Plain(f"[实时位置开启{suffix}]"))
    else:
        chain.chain.append(Plain("[实时位置已关闭]"))


async def handle_beacon(receiver, chain, event, _: str):
    """Render an ``m.beacon`` location update."""
    content = event.content or {}
    location = _resolve_location_payload(content)
    uri = location.get("uri") or location.get("geo_uri") or ""
    description = location.get("description") or _extract_text_repr(
        content.get(MSC1767_TEXT_KEY)
    )
    relates_to = content.get("m.relates_to") or {}
    related = relates_to.get("event_id") or ""
    suffix = f" (beacon: {related[:16]}...)" if related else ""
    if uri and description:
        chain.chain.append(Plain(f"[实时位置更新] {description} {uri}{suffix}"))
    elif uri:
        chain.chain.append(Plain(f"[实时位置更新] {uri}{suffix}"))
    elif description:
        chain.chain.append(Plain(f"[实时位置更新] {description}{suffix}"))
    else:
        chain.chain.append(Plain(f"[实时位置更新]{suffix}"))


BEACON_EVENT_TYPES = {
    M_BEACON_INFO,
    "org.matrix.msc3672.beacon_info",
    M_BEACON,
    "org.matrix.msc3672.beacon",
}
