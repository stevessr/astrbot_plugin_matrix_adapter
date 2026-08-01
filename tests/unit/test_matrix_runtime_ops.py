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
        self.message_mixin = load_module("client.message")
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
                self.outbound_tracker = (
                    outer.outbound_tracker_mod.MatrixOutboundTracker(
                        user_storage_dir=Path(outer.temp_dir.name)
                        / "store"
                        / "example.org"
                        / "bot",
                        store_path=Path(outer.temp_dir.name) / "store",
                        backend="json",
                    )
                )
                self.runtime_state = outer.runtime_state_mod.MatrixRuntimeState()

            async def _request(
                self,
                method,
                endpoint,
                data=None,
                params=None,
                authenticated=True,
                _retry_count=0,
            ):
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


class MatrixAdaptiveThreadReplyConfigTests(unittest.TestCase):
    def setUp(self):
        utils_mod = load_module("utils.utils")
        utils_pkg = sys.modules["astrbot_plugin_matrix_adapter.utils"]
        utils_pkg.parse_bool = utils_mod.parse_bool
        utils_pkg.MatrixUtils = utils_mod.MatrixUtils
        utils_pkg.mask_device_id = utils_mod.mask_device_id
        self.plugin_config = load_module("plugin_config")
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _init(self, config: dict):
        self.plugin_config.init_plugin_config(
            {"data_dir": self.temp_dir.name, **config}
        )
        return self.plugin_config.get_plugin_config()

    def test_adaptive_thread_reply_defaults_to_enabled(self):
        self.assertTrue(self._init({}).adaptive_thread_reply)

    def test_adaptive_thread_reply_can_be_disabled(self):
        self.assertFalse(
            self._init({"matrix_adaptive_thread_reply": False}).adaptive_thread_reply
        )

    def test_adaptive_thread_reply_accepts_string_values(self):
        self.assertFalse(
            self._init({"matrix_adaptive_thread_reply": "false"}).adaptive_thread_reply
        )
        self.assertTrue(
            self._init({"matrix_adaptive_thread_reply": "true"}).adaptive_thread_reply
        )

    def test_typing_defaults_to_disabled_and_read_receipt_to_enabled(self):
        config = self._init({})
        self.assertFalse(config.send_typing)
        self.assertTrue(config.send_read_receipt)

    def test_typing_and_read_receipt_switches_can_be_flipped(self):
        config = self._init(
            {"matrix_send_typing": True, "matrix_send_read_receipt": False}
        )
        self.assertTrue(config.send_typing)
        self.assertFalse(config.send_read_receipt)

    def test_typing_and_read_receipt_accept_string_values(self):
        config = self._init(
            {"matrix_send_typing": "true", "matrix_send_read_receipt": "false"}
        )
        self.assertTrue(config.send_typing)
        self.assertFalse(config.send_read_receipt)


class MatrixSyncReconnectTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_reconnect_cancels_inflight_sync_and_recovers(self):
        utils_mod = load_module("utils.utils")
        utils_pkg = sys.modules["astrbot_plugin_matrix_adapter.utils"]
        utils_pkg.parse_bool = utils_mod.parse_bool
        sync_manager_mod = load_module("sync.core")

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


class MatrixMessageOverrideMixinTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        utils_mod = load_module("utils.utils")
        utils_pkg = sys.modules["astrbot_plugin_matrix_adapter.utils"]
        utils_pkg.parse_bool = utils_mod.parse_bool
        utils_pkg.MatrixUtils = utils_mod.MatrixUtils
        utils_pkg.mask_device_id = utils_mod.mask_device_id
        self.override_mod = load_module("client.message_override_mixin")

    def _make_client(self):
        calls = []

        class FakeBase:
            async def send_message(
                self,
                room_id,
                msg_type,
                content,
                txn_id=None,
                tracker_metadata=None,
            ):
                calls.append(("send_message", room_id, msg_type, dict(content)))
                return {"event_id": "$sent"}

            async def get_event(self, room_id, event_id):
                calls.append(("get_event", room_id, event_id))
                return {"event_id": event_id, "content": {"body": "from server"}}

            async def room_messages(
                self,
                room_id,
                from_token=None,
                to_token=None,
                direction="b",
                limit=10,
            ):
                calls.append(("room_messages", room_id, direction, limit))
                return {"chunk": []}

        class FakeClient(self.override_mod.MessageOverrideMixin, FakeBase):
            pass

        return FakeClient(), calls

    async def test_without_hooks_everything_passes_through(self):
        client, calls = self._make_client()

        sent = await client.send_message(
            "!room:example.org", "m.room.message", {"body": "hi"}
        )
        event = await client.get_event("!room:example.org", "$evt:example.org")
        history = await client.room_messages("!room:example.org", limit=5)

        self.assertEqual(sent, {"event_id": "$sent"})
        self.assertEqual(event["content"]["body"], "from server")
        self.assertEqual(history, {"chunk": []})
        self.assertEqual(
            calls,
            [
                ("send_message", "!room:example.org", "m.room.message", {"body": "hi"}),
                ("get_event", "!room:example.org", "$evt:example.org"),
                ("room_messages", "!room:example.org", "b", 5),
            ],
        )

    async def test_before_send_hooks_chain_in_registration_order(self):
        client, calls = self._make_client()

        class UpperHook:
            async def before_send_message(self, room_id, msg_type, content):
                return {**content, "body": content["body"].upper()}

        class SuffixHook:
            # 同步钩子同样受支持
            def before_send_message(self, room_id, msg_type, content):
                return {**content, "body": content["body"] + "!"}

        self.assertTrue(client.register_message_hook(UpperHook()))
        self.assertTrue(client.register_message_hook(SuffixHook()))

        await client.send_message("!room:example.org", "m.room.message", {"body": "hi"})

        self.assertEqual(calls[0][3], {"body": "HI!"})

    async def test_after_send_hook_rewrites_response(self):
        client, _ = self._make_client()

        class TagHook:
            async def after_send_message(self, room_id, msg_type, content, response):
                return {**response, "tagged": True}

        client.register_message_hook(TagHook())

        response = await client.send_message(
            "!room:example.org", "m.room.message", {"body": "hi"}
        )
        self.assertEqual(response, {"event_id": "$sent", "tagged": True})

    async def test_before_get_event_hook_short_circuits_request(self):
        client, calls = self._make_client()

        class CacheHook:
            async def before_get_event(self, room_id, event_id):
                return {"event_id": event_id, "content": {"body": "cached"}}

        client.register_message_hook(CacheHook())

        event = await client.get_event("!room:example.org", "$evt:example.org")

        self.assertEqual(event["content"]["body"], "cached")
        self.assertEqual(calls, [])

    async def test_after_get_event_hook_rewrites_event(self):
        client, calls = self._make_client()

        class DecorateHook:
            async def after_get_event(self, room_id, event_id, event):
                return {**event, "decorated": True}

        client.register_message_hook(DecorateHook())

        event = await client.get_event("!room:example.org", "$evt:example.org")

        self.assertTrue(event["decorated"])
        self.assertEqual(len(calls), 1)

    async def test_before_room_messages_hook_rewrites_params_in_place(self):
        client, calls = self._make_client()

        class ClampHook:
            async def before_room_messages(self, room_id, params):
                params["limit"] = min(params.get("limit", 10), 20)
                params["direction"] = "f"
                return None

        client.register_message_hook(ClampHook())

        await client.room_messages("!room:example.org", limit=500)

        self.assertEqual(calls, [("room_messages", "!room:example.org", "f", 20)])

    async def test_before_room_messages_hook_can_short_circuit(self):
        client, calls = self._make_client()

        class CacheHook:
            async def before_room_messages(self, room_id, params):
                return {"chunk": [{"event_id": "$cached"}]}

        client.register_message_hook(CacheHook())

        history = await client.room_messages("!room:example.org")

        self.assertEqual(history["chunk"][0]["event_id"], "$cached")
        self.assertEqual(calls, [])

    async def test_failing_hook_does_not_break_the_call(self):
        client, calls = self._make_client()

        class BoomHook:
            async def before_send_message(self, room_id, msg_type, content):
                raise RuntimeError("boom")

        class LaterHook:
            async def before_send_message(self, room_id, msg_type, content):
                return {**content, "body": "recovered"}

        client.register_message_hook(BoomHook())
        client.register_message_hook(LaterHook())

        response = await client.send_message(
            "!room:example.org", "m.room.message", {"body": "hi"}
        )

        self.assertEqual(response, {"event_id": "$sent"})
        # 抛异常的钩子被跳过，后续钩子仍然生效
        self.assertEqual(calls[0][3], {"body": "recovered"})

    async def test_registration_rejects_duplicates_and_hookless_objects(self):
        client, _ = self._make_client()

        class Hook:
            async def before_send_message(self, room_id, msg_type, content):
                return None

        hook = Hook()
        self.assertTrue(client.register_message_hook(hook))
        self.assertFalse(client.register_message_hook(hook))
        self.assertFalse(client.register_message_hook(object()))
        self.assertFalse(client.register_message_hook(None))
        self.assertEqual(len(client.message_hooks), 1)

        self.assertTrue(client.unregister_message_hook(hook))
        self.assertFalse(client.unregister_message_hook(hook))
        self.assertEqual(client.message_hooks, [])

    async def test_hooks_are_per_instance(self):
        first, _ = self._make_client()
        second, _ = self._make_client()

        class Hook:
            async def before_send_message(self, room_id, msg_type, content):
                return None

        first.register_message_hook(Hook())

        self.assertEqual(len(first.message_hooks), 1)
        self.assertEqual(second.message_hooks, [])

    def test_real_client_resolves_wrapped_methods_to_the_override_mixin(self):
        """MRO 顺序保证拦截生效，且 super() 能落到真实实现上。"""
        http_client = load_module("client.http_client")
        client_cls = http_client.MatrixHTTPClient
        mro = client_cls.__mro__
        names = [cls.__name__ for cls in mro]

        # 三个被包装的方法都必须先解析到 MessageOverrideMixin
        for method in ("send_message", "get_event", "room_messages"):
            owner = next(cls.__name__ for cls in mro if method in cls.__dict__)
            self.assertEqual(owner, "MessageOverrideMixin", method)

        # 真实实现仍然在 MRO 后段，super() 调用不会落空
        self.assertLess(names.index("MessageOverrideMixin"), names.index("RoomMixin"))
        self.assertLess(
            names.index("MessageOverrideMixin"), names.index("MessageMixin")
        )
        self.assertIn("send_message", http_client.MessageMixin.__dict__)
        self.assertIn(
            "get_event",
            sys.modules[
                "astrbot_plugin_matrix_adapter.client.room_core_mixin"
            ].RoomCoreMixin.__dict__,
        )
