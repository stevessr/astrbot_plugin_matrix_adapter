import asyncio
import sys
import tempfile
import unittest

from test_matrix_new_spec_compat import load_module


class MatrixReadReceiptConfigTests(unittest.TestCase):
    def setUp(self):
        utils_mod = load_module("utils.utils")
        utils_pkg = sys.modules["astrbot_plugin_matrix_adapter.utils"]
        utils_pkg.parse_bool = utils_mod.parse_bool
        utils_pkg.MatrixUtils = utils_mod.MatrixUtils
        utils_pkg.mask_device_id = utils_mod.mask_device_id
        self.plugin_config = load_module("config.plugin")
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _init(self, config: dict):
        self.plugin_config.init_plugin_config(
            {"data_dir": self.temp_dir.name, **config}
        )
        return self.plugin_config.get_plugin_config()

    def test_read_receipt_type_defaults_to_public(self):
        config = self._init({})
        self.assertEqual(config.read_receipt_type, "public")
        self.assertTrue(config.send_read_receipt)

    def test_legacy_boolean_is_still_migrated(self):
        config = self._init({"matrix_send_read_receipt": False})
        self.assertEqual(config.read_receipt_type, "none")
        self.assertFalse(config.send_read_receipt)

    def test_explicit_type_wins_over_legacy_boolean(self):
        config = self._init(
            {
                "matrix_read_receipt_type": "private",
                "matrix_send_read_receipt": False,
            }
        )
        self.assertEqual(config.read_receipt_type, "private")
        self.assertTrue(config.send_read_receipt)

    def test_batch_interval_is_normalized(self):
        config = self._init(
            {
                "matrix_read_receipt_type": "batch",
                "matrix_read_receipt_batch_interval_ms": 50,
            }
        )
        self.assertEqual(config.read_receipt_type, "batch")
        self.assertEqual(config.read_receipt_batch_interval_ms, 100)


class MatrixReadReceiptDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.delivery = load_module("processors.event_lib.msg.dispatch.delivery")

        class FakeClient:
            def __init__(self):
                self.calls = []

            async def send_read_receipt(
                self, room_id, event_id, thread_id=None
            ):
                self.calls.append(("public", room_id, event_id, thread_id))
                return {}

            async def send_read_receipt_private(
                self, room_id, event_id, thread_id=None
            ):
                self.calls.append(("private", room_id, event_id, thread_id))
                return {}

        class Harness(self.delivery.MatrixEventProcessorMessagesDeliveryMixin):
            def __init__(self):
                self.client = FakeClient()

        self.harness = Harness()

    async def asyncTearDown(self):
        task = getattr(self.harness, "_read_receipt_batch_task", None)
        if task is not None and not task.done():
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_private_and_public_use_distinct_matrix_receipt_types(self):
        await self.harness._send_configured_read_receipt(
            "!room:example.org", "$private", "private", None
        )
        await self.harness._send_configured_read_receipt(
            "!room:example.org", "$public", "public", "$thread"
        )
        self.assertEqual(
            self.harness.client.calls,
            [
                ("private", "!room:example.org", "$private", None),
                ("public", "!room:example.org", "$public", "$thread"),
            ],
        )

    async def test_batch_window_is_lazy_fixed_and_coalesces_per_room(self):
        self.assertIsNone(
            getattr(self.harness, "_read_receipt_batch_task", None)
        )

        self.harness._queue_batched_read_receipt(
            "!room:example.org", "$first", None, 100
        )
        first_task = self.harness._read_receipt_batch_task
        self.assertIsNotNone(first_task)

        await asyncio.sleep(0.02)
        self.harness._queue_batched_read_receipt(
            "!room:example.org", "$latest", "$thread", 100
        )
        self.assertIs(self.harness._read_receipt_batch_task, first_task)

        await asyncio.sleep(0.11)
        self.assertEqual(
            self.harness.client.calls,
            [("public", "!room:example.org", "$latest", "$thread")],
        )
        self.assertIsNone(
            getattr(self.harness, "_read_receipt_batch_task", None)
        )


class MatrixNoticeModeTests(unittest.TestCase):
    def test_notice_switch_resolves_text_msgtype(self):
        common = load_module("sender.events.common")
        self.assertEqual(common.resolve_text_msgtype(False), "m.text")
        self.assertEqual(common.resolve_text_msgtype(True), "m.notice")


if __name__ == "__main__":
    unittest.main()
