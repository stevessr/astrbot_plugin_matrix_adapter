"""
Sync manager dispatch mixin
Provides sync response dispatch to registered callbacks
"""

import asyncio
from collections.abc import Callable

from astrbot.api import logger


class MatrixSyncManagerDispatchMixin:
    """Event dispatch logic for MatrixSyncManager."""

    async def _dispatch_events(self, sync_response: dict) -> None:
        """Dispatch sync response fields to registered callbacks."""
        tasks: list[asyncio.Task] = []

        # 1. To-device events — processed first (may contain room keys needed
        #    to decrypt room events in the same sync response).
        to_device = sync_response.get("to_device", {})
        events = to_device.get("events", [])
        if events and self.on_to_device_event:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_to_device_event", self.on_to_device_event, events
                )
            )
            tasks.append(task)

        # 2. Device list changes — pass full dict (original callback interface)
        device_lists = sync_response.get("device_lists", {})
        if device_lists and self.on_device_lists:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_device_lists", self.on_device_lists, device_lists
                )
            )
            tasks.append(task)

        # 3. One-time keys count + unused fallback key types
        device_one_time_keys_count = sync_response.get("device_one_time_keys_count", {})
        unused_fallback_key_types = sync_response.get(
            "device_unused_fallback_key_types"
        )
        if device_one_time_keys_count and self.on_device_one_time_keys_count:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_device_one_time_keys_count",
                    self.on_device_one_time_keys_count,
                    device_one_time_keys_count,
                    unused_fallback_key_types,
                )
            )
            tasks.append(task)

        # 4. Presence
        presence = sync_response.get("presence", {})
        presence_events = presence.get("events", [])
        if presence_events and self.on_presence_event:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_presence_event", self.on_presence_event, presence_events
                )
            )
            tasks.append(task)

        # 5. Account data
        account_data = sync_response.get("account_data", {})
        account_data_events = account_data.get("events", [])
        if account_data_events and self.on_account_data:
            task = asyncio.create_task(
                self._run_callback_with_guard(
                    "on_account_data", self.on_account_data, account_data_events
                )
            )
            tasks.append(task)

        # 6. Room events — process in parallel
        rooms = sync_response.get("rooms", {})
        room_tasks = []

        # Join events
        join_rooms = rooms.get("join", {})
        for room_id, room_data in join_rooms.items():
            if self.on_room_event:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_room_event:{room_id}",
                            self.on_room_event,
                            room_id,
                            room_data,
                        )
                    )
                )
            # Ephemeral events per room
            ephemeral = room_data.get("ephemeral", {})
            ephemeral_events = ephemeral.get("events", [])
            if ephemeral_events and self.on_ephemeral_event:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_ephemeral_event:{room_id}",
                            self.on_ephemeral_event,
                            room_id,
                            ephemeral_events,
                        )
                    )
                )
            # Room account data
            room_account_data = room_data.get("account_data", {})
            room_account_data_events = room_account_data.get("events", [])
            if room_account_data_events and self.on_room_account_data:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_room_account_data:{room_id}",
                            self.on_room_account_data,
                            room_id,
                            room_account_data_events,
                        )
                    )
                )

        # Invite events
        invite_rooms = rooms.get("invite", {})
        for room_id, invite_data in invite_rooms.items():
            if self.on_invite:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_invite:{room_id}",
                            self.on_invite,
                            room_id,
                            invite_data,
                        )
                    )
                )

        # Leave events
        leave_rooms = rooms.get("leave", {})
        for room_id, leave_data in leave_rooms.items():
            if self.on_leave:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_leave:{room_id}",
                            self.on_leave,
                            room_id,
                            leave_data,
                        )
                    )
                )

        # Knock events (MSC2403) — rooms the user has knocked on
        # where membership is still pending.
        knocked_rooms = rooms.get("knocked", {})
        for room_id, knock_data in knocked_rooms.items():
            if self.on_knock:
                room_tasks.append(
                    asyncio.create_task(
                        self._run_callback_with_guard(
                            f"on_knock:{room_id}",
                            self.on_knock,
                            room_id,
                            knock_data,
                        )
                    )
                )

        tasks.extend(room_tasks)

        # Track and await all callbacks
        self._active_callback_tasks.update(tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._active_callback_tasks.difference_update(tasks)

    async def _run_callback_with_guard(
        self,
        callback_name: str,
        callback: Callable,
        *args,
    ) -> None:
        """Run a single callback with timeout protection."""
        timeout = (
            self._retry_policy.callback_timeout
            if hasattr(self, "_retry_policy") and self._retry_policy is not None
            else 30
        )
        try:
            if timeout > 0:
                await asyncio.wait_for(callback(*args), timeout=timeout)
            else:
                await callback(*args)
        except asyncio.TimeoutError:
            logger.warning(f"Sync callback timed out: {callback_name} ({timeout:.1f}s)")
        except Exception as e:
            logger.error(f"Sync callback failed: {callback_name} ({e})")
