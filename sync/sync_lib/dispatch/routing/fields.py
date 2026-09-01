"""Global sync-response field dispatch."""

import asyncio


class MatrixSyncManagerEventRoutingFieldsMixin:
    """Dispatch non-room sync response fields to callbacks."""

    def _dispatch_global_fields(self, sync_response: dict, tasks: list) -> None:
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

        # 3. One-time keys count + unused fallback key types.
        # Matrix v1.17 clarifies that device_one_time_keys_count may be omitted
        # precisely when there are no unclaimed OTKs. Therefore absence is an
        # actionable zero-count state, not a reason to skip key maintenance.
        device_one_time_keys_count = sync_response.get("device_one_time_keys_count", {})
        if not isinstance(device_one_time_keys_count, dict):
            device_one_time_keys_count = {}
        unused_fallback_key_types = sync_response.get(
            "device_unused_fallback_key_types"
        )
        if self.on_device_one_time_keys_count:
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
