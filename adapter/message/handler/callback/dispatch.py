"""Final dispatch for inbound callbacks."""

from astrbot.api import logger

from .....constants import MSGTYPE_NOTICE


async def _resolve_server_msc4357_advertisement(adapter) -> bool | None:
    """Probe and cache an optional homeserver MSC4357 /versions hint."""

    client = getattr(adapter, "client", None)
    if client is None:
        return None

    if getattr(client, "_msc4357_server_probe_done", False):
        return getattr(client, "_msc4357_server_advertisement", None)

    probe = getattr(client, "get_msc4357_server_advertisement", None)
    if not callable(probe):
        client._msc4357_server_probe_done = True
        client._msc4357_server_advertisement = None
        return None

    try:
        advertised = await probe()
    except Exception as exc:
        # MSC4357 has no normative /versions flag. A discovery failure must not
        # disable a feature which otherwise works through ordinary m.replace.
        logger.debug(f"MSC4357 服务器能力提示探测失败，按未知处理: {exc}")
        advertised = None

    if advertised not in (True, False):
        advertised = None
    client._msc4357_server_probe_done = True
    client._msc4357_server_advertisement = advertised
    return advertised


async def _resolve_room_live_messaging_allowed(adapter, room) -> bool:
    """Resolve MSC4357 room policy, actively probing the homeserver if needed."""

    cached = getattr(room, "live_messaging_enabled", None)
    if isinstance(cached, bool):
        return cached

    # ``None`` has two meanings: "not queried yet" and "state absent/invalid".
    # Track the latter explicitly so an optional absent state event does not
    # trigger a network request for every message in the same room.
    if getattr(room, "live_messaging_policy_probed", False):
        return True

    room_id = getattr(room, "room_id", None)
    client = getattr(adapter, "client", None)
    probe = getattr(client, "get_room_live_messaging_allowed", None)
    if not room_id or not callable(probe):
        # Do not optimistically start a live stream when room policy probing
        # cannot be performed. Normal aggregated streaming still works.
        return False

    try:
        allowed = bool(await probe(room_id))
    except Exception as exc:
        # A transient probe failure should affect only this response. Do not
        # cache it: the next inbound message gets another chance to probe.
        logger.debug(
            f"MSC4357 房间策略探测失败，当前回复回退为普通流式聚合: "
            f"room={room_id}, error={exc}"
        )
        return False

    room.live_messaging_enabled = allowed
    room.live_messaging_policy_probed = True
    logger.debug(
        f"MSC4357 房间策略探测完成: room={room_id}, enabled={allowed}"
    )
    return allowed


async def _dispatch_message(adapter, abm, event, room, force_message_type: str):
    if getattr(event, "msgtype", None) == MSGTYPE_NOTICE:
        logger.debug(
            f"忽略 m.notice 自动分发，避免 bot notice 触发回复：event_id={getattr(event, 'event_id', '')}"
        )
        return

    if force_message_type != "stalk":
        room_allowed = await _resolve_room_live_messaging_allowed(adapter, room)
        if room_allowed:
            server_advertisement = await _resolve_server_msc4357_advertisement(
                adapter
            )
            # Only an explicit negative advertisement disables Live Messages.
            # Absence/unknown is allowed because MSC4357 requires no new
            # homeserver endpoint and deliberately has no normative flag.
            live_messaging_allowed = server_advertisement is not False
        else:
            live_messaging_allowed = False

        await adapter.handle_msg(
            abm,
            event_id=getattr(event, "event_id", None),
            room_live_messaging_enabled=live_messaging_allowed,
        )


__all__ = ["_dispatch_message"]
