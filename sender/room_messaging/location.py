"""Live-location beacon sender extensions."""

from typing import Any

from ...constants import (
    CONTENT_KEY_RELATES_TO,
    M_BEACON,
    M_BEACON_INFO,
    MSC1767_TEXT_KEY,
    MSC3488_ASSET_KEY,
    MSC3488_TS_KEY,
    REL_TYPE_REFERENCE,
)


class SenderLocationMixin:
    async def send_live_location_beacon_info(
        self,
        room_id: str,
        *,
        description: str | None = None,
        timeout_ms: int = 3600_000,
        live: bool = True,
        asset_type: str = "m.self",
    ) -> dict | None:
        """
        Publish a live-location ``m.beacon_info`` state event (MSC3489).

        The state key MUST be the sender's user ID. Once published, the sender
        can call :meth:`send_live_location_beacon` repeatedly to publish
        ``m.beacon`` events that update the location.
        """
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive for live location")
        user_id = getattr(self.client, "user_id", None)
        if not user_id:
            raise RuntimeError("client.user_id is required for beacon_info")

        ts_ms = int(self._now_ms())
        content: dict[str, Any] = {
            "live": bool(live),
            "timeout": int(timeout_ms),
            "m.ts": ts_ms,
            MSC3488_TS_KEY: ts_ms,
            MSC3488_ASSET_KEY: {"type": asset_type},
            "m.asset": {"type": asset_type},
        }
        if description:
            content["description"] = description

        return await self.client.set_room_state_event(
            room_id=room_id,
            event_type=M_BEACON_INFO,
            content=content,
            state_key=user_id,
        )

    async def send_live_location_beacon(
        self,
        room_id: str,
        beacon_info_event_id: str,
        latitude: float,
        longitude: float,
        *,
        accuracy_m: float | None = None,
        description: str | None = None,
    ) -> dict | None:
        """
        Publish a live-location ``m.beacon`` update (MSC3489).

        Args:
            beacon_info_event_id: The event ID of the ``m.beacon_info`` state event.
            latitude / longitude: Coordinates of the location update.
            accuracy_m: Optional horizontal accuracy in meters.
            description: Optional human-readable description.
        """
        if not beacon_info_event_id:
            raise ValueError("beacon_info_event_id is required")

        geo_uri = f"geo:{latitude},{longitude}"
        if accuracy_m and accuracy_m > 0:
            geo_uri += f";u={accuracy_m}"
        location_payload: dict[str, Any] = {"uri": geo_uri}
        if description:
            location_payload["description"] = description

        ts_ms = int(self._now_ms())
        content: dict[str, Any] = {
            "m.location": location_payload,
            "org.matrix.msc3488.location": dict(location_payload),
            "m.ts": ts_ms,
            MSC3488_TS_KEY: ts_ms,
            CONTENT_KEY_RELATES_TO: {
                "rel_type": REL_TYPE_REFERENCE,
                "event_id": beacon_info_event_id,
            },
            MSC1767_TEXT_KEY: description or geo_uri,
        }

        return await self.client.send_room_event(
            room_id=room_id,
            event_type=M_BEACON,
            content=content,
            txn_id=None,
        )


__all__ = ["SenderLocationMixin"]
