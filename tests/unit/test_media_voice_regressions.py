"""Regression tests for voice (m.audio) media handling.

Covers two reported bugs:

* issue #19 — the file and byte upload paths shared a method name, so the
  MRO resolved the file path's 4-positional-argument call to the byte path's
  keyword-only implementation, and uploads raised
  ``takes 1 positional argument but 5 were given``.
* issue #20 — ``m.audio`` events carry a generated filename in ``body``;
  AstrBot's STT appends to ``message_str``, so the filename leaked into the
  model prompt (``voice-message-1.ogg你好``).
"""

import sys
import types
import unittest
from pathlib import Path

from test_matrix_new_spec_compat import load_module


class MediaUploadResultConsumptionTests(unittest.IsolatedAsyncioTestCase):
    """The file and byte upload paths must each consume their own result."""

    async def asyncSetUp(self):
        self.upload_mod = load_module("client.media.upload")
        self.endpoint_mod = load_module("client.media.upload.endpoint")

    def _new_client(self):
        client = self.upload_mod.MediaUploadMixin.__new__(
            self.upload_mod.MediaUploadMixin
        )
        client._media_upload_cache = {}
        return client

    async def test_file_and_bytes_consumers_have_distinct_names(self):
        mixin = self.upload_mod.MediaUploadMixin
        self.assertTrue(hasattr(mixin, "_consume_file_upload_result"))
        self.assertTrue(hasattr(mixin, "_consume_bytes_upload_result"))
        self.assertFalse(hasattr(mixin, "_consume_upload_result"))

    async def test_file_path_consumes_with_file_signature(self):
        """A 4-positional-argument call (file upload) must not hit the byte path."""
        client = self._new_client()

        class _Reader:
            def hexdigest(self):
                return "abc123"

        payload = await client._consume_file_upload_result(
            {"content_uri": "mxc://example.org/file"},
            _Reader(),
            "path-key",
            "audio/ogg",
        )

        self.assertEqual(payload["content_uri"], "mxc://example.org/file")
        cached = set(client._media_upload_cache)
        self.assertIn("path-key", cached)
        self.assertTrue(
            any("abc123" in key for key in cached),
            f"digest cache key missing, got {cached}",
        )

    async def test_bytes_path_consumes_with_keyword_signature(self):
        client = self._new_client()
        payload = await client._consume_bytes_upload_result(
            response_data={"content_uri": "mxc://example.org/bytes"},
            cache_key="bytes-key",
        )
        self.assertEqual(payload["content_uri"], "mxc://example.org/bytes")
        self.assertIn("bytes-key", client._media_upload_cache)

    async def test_file_consumer_is_reached_through_the_composed_mixin(self):
        """MRO must resolve the file path call to the file implementation."""
        resolved = self.upload_mod.MediaUploadMixin._consume_file_upload_result
        self.assertIn("file", resolved.__module__)


class MediaUploadEndpointOrderTests(unittest.TestCase):
    """Uploads must prefer the endpoint defined by the Matrix specification."""

    def setUp(self):
        self.selection = load_module("client.media.upload.endpoint").__dict__[
            "MediaUploadEndpointSelectionMixin"
        ]

    def test_spec_upload_endpoint_is_tried_first(self):
        endpoints = self.selection._get_media_upload_endpoints()
        self.assertEqual(endpoints[0], "/_matrix/media/v3/upload")
        self.assertIn("/_matrix/client/v1/media/upload", endpoints)

    def test_404_falls_back_to_the_next_endpoint(self):
        self.assertTrue(
            self.selection._should_try_next_media_upload_endpoint(404, 0, 2)
        )
        self.assertFalse(
            self.selection._should_try_next_media_upload_endpoint(404, 1, 2)
        )
        self.assertFalse(
            self.selection._should_try_next_media_upload_endpoint(400, 0, 2)
        )

    def test_404_warning_names_the_failed_and_next_endpoint(self):
        retry_mod = load_module(
            "client.media.upload.file.upload.transfer.core.retry"
        )
        mixin = retry_mod.MediaUploadTransferRetryMixin
        captured = []

        class _Logger:
            def warning(self, message):
                captured.append(message)

        original_logger = retry_mod.logger
        retry_mod.logger = _Logger()
        try:
            action = mixin._decide_upload_status_action(
                types.SimpleNamespace(
                    _should_try_next_media_upload_endpoint=lambda *args: True
                ),
                404,
                "/_matrix/media/v3/upload",
                0,
                ["/_matrix/media/v3/upload", "/_matrix/client/v1/media/upload"],
                {},
                {},
                0,
            )
        finally:
            retry_mod.logger = original_logger

        self.assertEqual(action, ("switch", None))
        self.assertEqual(len(captured), 1)
        self.assertIn("not supported (404)", captured[0])
        self.assertIn("/_matrix/media/v3/upload", captured[0])
        self.assertIn("falling back to /_matrix/client/v1/media/upload", captured[0])


class MatrixAudioMessageStrTests(unittest.IsolatedAsyncioTestCase):
    """``m.audio`` filename placeholders must not reach the model prompt."""

    async def asyncSetUp(self):
        _hydrate_events_package()
        self.convert_mod = load_module("receiver.receiver_lib.convert")
        # The harness rebuilds the stub component classes on every load_module
        # call, so bind the Record class that core.py actually imported.
        core_module = sys.modules[
            "astrbot_plugin_matrix_adapter.receiver.receiver_lib.convert"
            ".operations.message.core.core"
        ]
        self.record_cls = core_module.Record
        self.message_components = sys.modules["astrbot.api.message_components"]

    def _receiver(self, *, record: bool):
        receiver = self.convert_mod.MatrixReceiverConvertMixin.__new__(
            self.convert_mod.MatrixReceiverConvertMixin
        )
        receiver.user_id = "@bot:example.org"
        receiver.bot_name = "bot"
        receiver.client = None
        receiver.mxc_converter = None
        receiver._assign_message_type = lambda message, room: None
        receiver._build_message_sender = lambda event, room: None
        receiver._parse_reply_event_id = lambda content: None

        Record = self.record_cls
        Plain = self.message_components.Plain

        if record:

            async def _handle(receiver, chain, event, msgtype):
                chain.chain.append(Record(file="/tmp/voice.ogg"))

        else:

            async def _handle(receiver, chain, event, msgtype):
                chain.chain.append(Plain(f"[语音下载失败：{event.body}]"))

        receiver._MSGTYPE_HANDLERS = {"m.audio": _handle}
        return receiver

    async def _convert(self, body: str, content: dict, *, record: bool = True):
        receiver = self._receiver(record=record)
        event = types.SimpleNamespace(
            content=content,
            body=body,
            event_id="$event",
            sender="@user:example.org",
            type="m.room.message",
            event_type=None,
        )
        room = types.SimpleNamespace(room_id="!room:example.org", is_group=False)
        return await receiver.convert_message(room, event)

    async def test_element_filename_placeholder_is_stripped(self):
        message = await self._convert(
            "voice-message-1731400000000.ogg",
            {
                "msgtype": "m.audio",
                "body": "voice-message-1731400000000.ogg",
                "url": "mxc://example.org/audio",
                "info": {"mimetype": "audio/ogg"},
            },
        )
        self.assertEqual(message.message_str, "")
        self.assertEqual(len(message.message), 1)

    async def test_legacy_voice_message_placeholder_is_stripped(self):
        message = await self._convert(
            "Voice message",
            {"msgtype": "m.audio", "body": "Voice message", "url": "mxc://x/y"},
        )
        self.assertEqual(message.message_str, "")

    async def test_real_caption_is_preserved(self):
        message = await self._convert(
            "听一下这段",
            {
                "msgtype": "m.audio",
                "body": "听一下这段",
                "filename": "voice.ogg",
                "url": "mxc://example.org/audio",
            },
        )
        self.assertEqual(message.message_str, "听一下这段")

    async def test_download_failure_keeps_original_body(self):
        message = await self._convert(
            "voice-message-1.ogg",
            {"msgtype": "m.audio", "body": "voice-message-1.ogg", "url": "mxc://x/y"},
            record=False,
        )
        self.assertEqual(message.message_str, "voice-message-1.ogg")

    async def test_text_messages_are_untouched(self):
        message = await self._convert("你好", {"msgtype": "m.text", "body": "你好"})
        self.assertEqual(message.message_str, "你好")


def _hydrate_events_package() -> None:
    """Execute the real ``receiver/events/__init__.py`` inside the test stub.

    The shared test harness registers ``receiver.events`` as a bare module
    with a ``__path__`` and never runs its ``__init__.py``, so the public
    handler names are missing when a deeper module imports them.
    """
    load_module("receiver.events.audio")  # installs the stub package chain
    package_name = "astrbot_plugin_matrix_adapter.receiver.events"
    events_pkg = sys.modules[package_name]
    if getattr(events_pkg, "BEACON_EVENT_TYPES", None) is not None:
        return
    events_pkg.__package__ = package_name
    init_path = Path(events_pkg.__path__[0]) / "__init__.py"
    code = compile(init_path.read_text(encoding="utf-8"), str(init_path), "exec")
    exec(code, events_pkg.__dict__)  # noqa: S102 - test harness only


if __name__ == "__main__":
    unittest.main()
