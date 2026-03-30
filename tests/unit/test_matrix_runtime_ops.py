import asyncio
import sys
import tempfile
import unittest
from pathlib import Path

from test_matrix_new_spec_compat import load_module


class MatrixOutboundTrackerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        utils_mod = load_module("utils.utils")
        utils_pkg = sys.modules["astrbot_plugin_matrix_adapter.utils"]
        utils_pkg.parse_bool = utils_mod.parse_bool
        utils_pkg.MatrixUtils = utils_mod.MatrixUtils
        utils_pkg.mask_device_id = utils_mod.mask_device_id
        plugin_config = load_module("plugin_config")
        self.temp_dir = tempfile.TemporaryDirectory()
        plugin_config.init_plugin_config({"data_dir": self.temp_dir.name})
        self.message_mixin = load_module("client.message_mixin")
        self.outbound_tracker_mod = load_module("outbound_tracker")
        self.runtime_state_mod = load_module("runtime_state")

    async def asyncTearDown(self):
        self.temp_dir.cleanup()

    def _make_client(self, *, fail_once: bool = False):
        outer = self

        class FakeClient(self.message_mixin.MessageMixin):
            def __init__(self):
                self.fail_once = fail_once
                self.calls = 0
                self.outbound_tracker = outer.outbound_tracker_mod.MatrixOutboundTracker(
                    user_storage_dir=Path(outer.temp_dir.name) / "store" / "example.org" / "bot",
                    store_path=Path(outer.temp_dir.name) / "store",
                    backend="json",
                )
                self.runtime_state = outer.runtime_state_mod.MatrixRuntimeState()

            async def _request(self, method, endpoint, data=None, params=None, authenticated=True, _retry_count=0):
                self.calls += 1
                if self.fail_once and self.calls == 1:
                    raise RuntimeError("boom")
                return {"event_id": f"$event{self.calls}"}

        return FakeClient()

    async def test_send_message_tracks_success(self):
        client = self._make_client()
        response = await client.send_message(
            room_id="!room:example.org",
            msg_type="m.room.message",
            content={"msgtype": "m.text", "body": "hello"},
            txn_id="txn-success",
        )
        self.assertEqual(response["event_id"], "$event1")
        self.assertEqual(client.outbound_tracker.summary()["sent"], 1)
        self.assertEqual(client.runtime_state.send_success_count, 1)

    async def test_failed_send_can_be_retried(self):
        client = self._make_client(fail_once=True)
        with self.assertRaises(RuntimeError):
            await client.send_message(
                room_id="!room:example.org",
                msg_type="m.room.message",
                content={"msgtype": "m.text", "body": "hello"},
                txn_id="txn-retry",
            )

        self.assertEqual(client.outbound_tracker.summary()["failed"], 1)
        self.assertEqual(client.runtime_state.send_failure_count, 1)

        results = await client.outbound_tracker.resend_pending(client, limit=10)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"])
        self.assertEqual(client.outbound_tracker.summary()["sent"], 1)


class MatrixSyncReconnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_reconnect_cancels_inflight_sync_and_recovers(self):
        utils_mod = load_module("utils.utils")
        utils_pkg = sys.modules["astrbot_plugin_matrix_adapter.utils"]
        utils_pkg.parse_bool = utils_mod.parse_bool
        sync_manager_mod = load_module("sync.sync_manager")

        class FakeClient:
            def __init__(self):
                self.calls = 0
                self.first_sync_cancelled = asyncio.Event()
                self.allow_later_sync = asyncio.Event()

            async def sync(self, since=None, timeout=None, full_state=None):
                self.calls += 1
                if self.calls == 1:
                    try:
                        await asyncio.Future()
                    except asyncio.CancelledError:
                        self.first_sync_cancelled.set()
                        raise
                await self.allow_later_sync.wait()
                return {"next_batch": f"batch-{self.calls}", "rooms": {}}

        client = FakeClient()
        manager = sync_manager_mod.MatrixSyncManager(client=client, sync_timeout=10)
        task = asyncio.create_task(manager.sync_forever())
        try:
            for _ in range(50):
                if client.calls >= 1:
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(manager.request_reconnect())
            await asyncio.wait_for(client.first_sync_cancelled.wait(), timeout=1)
            client.allow_later_sync.set()
            for _ in range(100):
                if manager.status_snapshot()["sync_success_count"] >= 1:
                    break
                await asyncio.sleep(0.01)
            self.assertGreaterEqual(manager.status_snapshot()["sync_success_count"], 1)
        finally:
            manager.stop()
            await asyncio.wait_for(task, timeout=1)
