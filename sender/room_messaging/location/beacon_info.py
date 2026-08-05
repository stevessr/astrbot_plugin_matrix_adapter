"""Live-location beacon_info state event sender."""

from typing import Any

from ....constants import (
    M_BEACON_INFO,
    MSC3488_ASSET_KEY,
    MSC3488_TS_KEY,
)


class SenderLocationBeaconInfoMixin:
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


__all__ = ["SenderLocationBeaconInfoMixin"]
