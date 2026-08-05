"""Live-location beacon update sender."""

from typing import Any

from ....constants import (
    CONTENT_KEY_RELATES_TO,
    M_BEACON,
    MSC1767_TEXT_KEY,
    MSC3488_TS_KEY,
    REL_TYPE_REFERENCE,
)


class SenderLocationBeaconMixin:
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


__all__ = ["SenderLocationBeaconMixin"]
