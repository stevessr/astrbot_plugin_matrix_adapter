import base64
import importlib
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_NAME = "astrbot_plugin_matrix_adapter"


def _install_astrbot_stubs() -> None:
    astrbot_module = sys.modules.setdefault("astrbot", types.ModuleType("astrbot"))
    api_module = sys.modules.setdefault("astrbot.api", types.ModuleType("astrbot.api"))
    setattr(astrbot_module, "api", api_module)

    class _Logger:
        def debug(self, *args, **kwargs):
            return None

        info = warning = error = debug

    api_module.logger = _Logger()

    star_module = sys.modules.setdefault(
        "astrbot.api.star", types.ModuleType("astrbot.api.star")
    )

    class StarTools:
        @staticmethod
        def get_data_dir(_name: str):
            return Path(tempfile.gettempdir()) / "astrbot_plugin_matrix_adapter"

    star_module.StarTools = StarTools

    message_components = sys.modules.setdefault(
        "astrbot.api.message_components",
        types.ModuleType("astrbot.api.message_components"),
    )

    class BaseMessageComponent:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class Plain:
        def __init__(self, text: str):
            self.text = text

    class At(BaseMessageComponent):
        def __init__(self, qq: str, name: str | None = None, **kwargs):
            super().__init__(qq=qq, name=name or qq, **kwargs)

    class AtAll(BaseMessageComponent):
        pass

    class Location(BaseMessageComponent):
        pass

    class Reply(BaseMessageComponent):
        pass

    class Record(BaseMessageComponent):
        def __init__(self, file=None, url=None, **kwargs):
            super().__init__(file=file, url=url, **kwargs)

        @classmethod
        def fromFileSystem(cls, file_path: str):
            return cls(file=file_path)

        @classmethod
        def fromURL(cls, url: str):
            return cls(url=url)

        async def convert_to_file_path(self):
            if not getattr(self, "file", None):
                raise RuntimeError("Record stub missing file path")
            return self.file

    class ComponentType:
        Unknown = "unknown"

    message_components.BaseMessageComponent = BaseMessageComponent
    message_components.At = At
    message_components.AtAll = AtAll
    message_components.Location = Location
    message_components.Plain = Plain
    message_components.Record = Record
    message_components.Reply = Reply
    message_components.ComponentType = ComponentType


def _install_aiohttp_stub() -> None:
    try:
        import aiohttp as _aiohttp  # type: ignore

        sys.modules["aiohttp"] = _aiohttp
        return
    except ImportError:
        pass

    aiohttp_module = sys.modules.setdefault("aiohttp", types.ModuleType("aiohttp"))

    class ClientTimeout:
        def __init__(self, total=None, **kwargs):
            self.total = total

    class ClientSession:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("ClientSession stub should be patched in tests")

    aiohttp_module.ClientTimeout = ClientTimeout
    aiohttp_module.ClientSession = ClientSession


def _install_package_stubs() -> None:
    package_paths = {
        PACKAGE_NAME: REPO_ROOT,
        f"{PACKAGE_NAME}.auth": REPO_ROOT / "auth",
        f"{PACKAGE_NAME}.client": REPO_ROOT / "client",
        f"{PACKAGE_NAME}.e2ee": REPO_ROOT / "e2ee",
        f"{PACKAGE_NAME}.processors": REPO_ROOT / "processors",
        f"{PACKAGE_NAME}.receiver": REPO_ROOT / "receiver",
        f"{PACKAGE_NAME}.receiver.handlers": REPO_ROOT / "receiver" / "handlers",
        f"{PACKAGE_NAME}.sender": REPO_ROOT / "sender",
        f"{PACKAGE_NAME}.sender.handlers": REPO_ROOT / "sender" / "handlers",
        f"{PACKAGE_NAME}.utils": REPO_ROOT / "utils",
    }
    for name, path in package_paths.items():
        module = sys.modules.setdefault(name, types.ModuleType(name))
        module.__path__ = [str(path)]


def load_module(relative_name: str):
    _install_astrbot_stubs()
    _install_aiohttp_stub()
    _install_package_stubs()
    return importlib.import_module(f"{PACKAGE_NAME}.{relative_name}")


class MatrixPollCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_poll_defaults_and_stable_handler(self):
        components = load_module("components")
        poll_handler = load_module("receiver.handlers.poll")

        poll = components.Poll("喝什么？", ["茶", "咖啡"])
        self.assertEqual(poll.event_type, "m.poll.start")
        self.assertEqual(poll.poll_key, "m.poll")

        chain = types.SimpleNamespace(chain=[])
        event = types.SimpleNamespace(
            content={
                "m.poll": {
                    "question": {"body": "喝什么？"},
                    "answers": [
                        {"id": "answer_1", "body": "茶"},
                        {"id": "answer_2", "body": "咖啡"},
                    ],
                }
            }
        )

        await poll_handler.handle_poll_start(None, chain, event, "m.poll.start")
        self.assertEqual(chain.chain[0].text, "[Poll] 喝什么？ | Options: 茶, 咖啡")

    async def test_stable_handler_accepts_extensible_poll_fields(self):
        poll_handler = load_module("receiver.handlers.poll")

        chain = types.SimpleNamespace(chain=[])
        event = types.SimpleNamespace(
            content={
                "m.poll": {
                    "question": {"m.text": [{"body": "喝什么？"}]},
                    "answers": [
                        {"m.id": "answer_1", "m.text": [{"body": "茶"}]},
                        {"m.id": "answer_2", "m.text": [{"body": "咖啡"}]},
                    ],
                },
                "m.text": [{"body": "喝什么？\n1. 茶\n2. 咖啡"}],
            }
        )

        await poll_handler.handle_poll_start(None, chain, event, "m.poll.start")
        self.assertEqual(chain.chain[0].text, "[Poll] 喝什么？ | Options: 茶, 咖啡")

    async def test_stable_response_handler_reads_m_selections(self):
        poll_handler = load_module("receiver.handlers.poll")

        chain = types.SimpleNamespace(chain=[])
        event = types.SimpleNamespace(
            content={
                "m.selections": ["answer_1", "answer_3"],
                "m.relates_to": {
                    "rel_type": "m.reference",
                    "event_id": "$poll1234567890:example.org",
                },
            }
        )

        await poll_handler.handle_poll_response(None, chain, event, "m.poll.response")
        self.assertIn("Selected: answer_1, answer_3", chain.chain[0].text)
        self.assertIn("responding to", chain.chain[0].text)

    async def test_stable_sender_emits_extensible_poll_fields(self):
        poll_sender = load_module("sender.handlers.poll")
        captured = {}

        async def fake_send_content(
            client,
            content,
            room_id,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            e2ee_manager,
            msg_type="m.room.message",
        ):
            captured["content"] = content
            captured["room_id"] = room_id
            captured["msg_type"] = msg_type
            return {"event_id": "$event"}

        with mock.patch.object(poll_sender, "send_content", new=fake_send_content):
            await poll_sender.send_poll(
                client=object(),
                room_id="!room:example.org",
                question="喝什么？",
                answers=["茶", "咖啡"],
                reply_to=None,
                thread_root=None,
                use_thread=False,
                is_encrypted_room=False,
                e2ee_manager=None,
            )

        content = captured["content"]
        self.assertEqual(captured["msg_type"], "m.poll.start")
        self.assertEqual(content["m.poll"]["question"]["m.text"], [{"body": "喝什么？"}])
        self.assertEqual(content["m.poll"]["answers"][0]["m.id"], "answer_1")
        self.assertEqual(content["m.poll"]["answers"][0]["m.text"], [{"body": "茶"}])
        self.assertEqual(content["m.text"][0]["body"], "喝什么？\n1. 茶\n2. 咖啡")
        self.assertEqual(content["body"], "喝什么？\n1. 茶\n2. 咖啡")

    async def test_stable_sender_response_uses_m_selections(self):
        poll_sender = load_module("sender.handlers.poll")
        captured = {}

        async def fake_send_content(
            client,
            content,
            room_id,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            e2ee_manager,
            msg_type="m.room.message",
        ):
            captured["content"] = content
            captured["room_id"] = room_id
            captured["msg_type"] = msg_type
            return {"event_id": "$response"}

        with mock.patch.object(poll_sender, "send_content", new=fake_send_content):
            await poll_sender.send_poll_response(
                client=object(),
                room_id="!room:example.org",
                poll_start_event_id="$poll:example.org",
                answer_ids=["answer_1", "answer_2"],
            )

        self.assertEqual(captured["msg_type"], "m.poll.response")
        self.assertEqual(captured["content"]["m.selections"], ["answer_1", "answer_2"])
        self.assertEqual(
            captured["content"]["m.relates_to"],
            {"rel_type": "m.reference", "event_id": "$poll:example.org"},
        )
        self.assertNotIn("m.poll", captured["content"])


class MatrixLocationCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_location_sender_adds_text_fallback(self):
        location_sender = load_module("sender.handlers.location")
        location_cls = sys.modules["astrbot.api.message_components"].Location
        captured = {}

        async def fake_send_content(
            client,
            content,
            room_id,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            e2ee_manager,
            msg_type="m.room.message",
        ):
            captured["content"] = content
            captured["room_id"] = room_id
            captured["msg_type"] = msg_type
            return {"event_id": "$location"}

        segment = location_cls(
            lat="51.5008",
            lon="0.1247",
            title="Big Ben, London, UK",
            content="",
        )

        with mock.patch.object(location_sender, "send_content", new=fake_send_content):
            await location_sender.send_location(
                client=object(),
                segment=segment,
                room_id="!room:example.org",
                reply_to=None,
                thread_root=None,
                use_thread=False,
                is_encrypted_room=False,
                e2ee_manager=None,
            )

        self.assertEqual(captured["msg_type"], "m.room.message")
        self.assertEqual(captured["content"]["msgtype"], "m.location")
        self.assertEqual(captured["content"]["body"], "Big Ben, London, UK")
        self.assertEqual(captured["content"]["geo_uri"], "geo:51.5008,0.1247")
        self.assertEqual(
            captured["content"]["m.text"], [{"body": "Big Ben, London, UK"}]
        )
        self.assertEqual(
            captured["content"]["m.location"],
            {"uri": "geo:51.5008,0.1247", "description": "Big Ben, London, UK"},
        )
        self.assertEqual(captured["content"]["m.asset"], {"type": "m.self"})
        self.assertEqual(
            captured["content"]["org.matrix.msc3488.location"],
            {"uri": "geo:51.5008,0.1247", "description": "Big Ben, London, UK"},
        )
        self.assertEqual(
            captured["content"]["org.matrix.msc3488.asset"], {"type": "m.self"}
        )

    async def test_location_handler_accepts_extensible_fallback_fields(self):
        location_handler = load_module("receiver.handlers.location")

        chain = types.SimpleNamespace(chain=[])
        event = types.SimpleNamespace(
            body="",
            content={
                "m.location": {"uri": "geo:51.5008,0.1247"},
                "m.text": [{"body": "Big Ben, London, UK"}],
            },
        )

        await location_handler.handle_location(None, chain, event, "m.location")
        self.assertEqual(chain.chain[0].text, "[位置] Big Ben, London, UK geo:51.5008,0.1247")

    async def test_location_handler_accepts_unstable_asset_and_pin_type(self):
        location_handler = load_module("receiver.handlers.location")

        chain = types.SimpleNamespace(chain=[])
        event = types.SimpleNamespace(
            body="",
            content={
                "org.matrix.msc3488.location": {
                    "uri": "geo:51.5008,0.1247",
                    "description": "Big Ben, London, UK",
                },
                "org.matrix.msc3488.asset": {"type": "m.pin"},
            },
        )

        await location_handler.handle_location(
            None, chain, event, "org.matrix.msc3488.location"
        )
        self.assertEqual(
            chain.chain[0].text,
            "[位置标记] Big Ben, London, UK geo:51.5008,0.1247",
        )

    async def test_event_processor_accepts_top_level_location_events(self):
        location_handler = load_module("receiver.handlers.location")

        module_name = f"{PACKAGE_NAME}.processors.event_processor"
        sys.modules.pop(module_name, None)

        def _make_module(name: str, **attrs):
            module = types.ModuleType(name)
            for key, value in attrs.items():
                setattr(module, key, value)
            return module

        class _MatrixEventProcessorMembers:
            pass

        class _MatrixEventProcessorStreams:
            pass

        stubs = {
            f"{PACKAGE_NAME}.constants": _make_module(
                f"{PACKAGE_NAME}.constants",
                MAX_PROCESSED_MESSAGES_1000=1000,
                TIMESTAMP_BUFFER_MS_1000=1000,
                GROUP_CHAT_MIN_MEMBERS_2=2,
            ),
            f"{PACKAGE_NAME}.plugin_config": _make_module(
                f"{PACKAGE_NAME}.plugin_config",
                get_plugin_config=lambda: types.SimpleNamespace(
                    storage_backend_config=None
                ),
            ),
            f"{PACKAGE_NAME}.processors.event_processor_members": _make_module(
                f"{PACKAGE_NAME}.processors.event_processor_members",
                MatrixEventProcessorMembers=_MatrixEventProcessorMembers,
            ),
            f"{PACKAGE_NAME}.processors.event_processor_streams": _make_module(
                f"{PACKAGE_NAME}.processors.event_processor_streams",
                MatrixEventProcessorStreams=_MatrixEventProcessorStreams,
            ),
            f"{PACKAGE_NAME}.utils": _make_module(
                f"{PACKAGE_NAME}.utils",
                parse_bool=lambda value, default=False: default,
            ),
        }

        with mock.patch.dict(sys.modules, stubs):
            event_processor = importlib.import_module(module_name)

            for event_type, asset_key in (
                ("m.location", "m.asset"),
                ("org.matrix.msc3488.location", "org.matrix.msc3488.asset"),
            ):
                with self.subTest(event_type=event_type):
                    captured = {}

                    async def fake_process_message_event(room, event):
                        captured["room_id"] = room.room_id
                        captured["event"] = event

                    processor = event_processor.MatrixEventProcessor.__new__(
                        event_processor.MatrixEventProcessor
                    )
                    processor._process_message_event = fake_process_message_event

                    room = types.SimpleNamespace(room_id="!room:example.org")
                    await event_processor.MatrixEventProcessor._handle_event(
                        processor,
                        room,
                        {
                            "type": event_type,
                            "event_id": "$location:example.org",
                            "sender": "@alice:example.org",
                            "origin_server_ts": 123,
                            "content": {
                                "uri": "geo:51.5008,0.1247",
                                "description": "Big Ben, London, UK",
                                asset_key: {"type": "m.pin"},
                            },
                        },
                    )

                    self.assertEqual(captured["room_id"], "!room:example.org")
                    self.assertEqual(captured["event"].msgtype, "m.location")
                    self.assertEqual(captured["event"].body, "Big Ben, London, UK")

                    chain = types.SimpleNamespace(chain=[])
                    await location_handler.handle_location(
                        None,
                        chain,
                        captured["event"],
                        captured["event"].event_type,
                    )
                    self.assertEqual(
                        chain.chain[0].text,
                        "[位置标记] Big Ben, London, UK geo:51.5008,0.1247",
                    )


class MatrixVoiceCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_audio_sender_emits_voice_indicator_and_unstable_audio_duration(self):
        audio_sender = load_module("sender.handlers.audio")
        record_cls = sys.modules["astrbot.api.message_components"].Record
        captured = {}

        class FakeProcess:
            returncode = 0

            async def communicate(self):
                return (b'{"format": {"duration": "1.234"}}', b"")

        class FakeClient:
            async def upload_file_path(self, **kwargs):
                return {"content_uri": "mxc://example.org/voice"}

        async def fake_send_content(
            client,
            content,
            room_id,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            e2ee_manager,
            msg_type="m.room.message",
        ):
            captured["content"] = content
            captured["msg_type"] = msg_type
            return {"event_id": "$voice"}

        with tempfile.NamedTemporaryFile(suffix=".ogg") as audio_file:
            audio_file.write(b"voice-bytes")
            audio_file.flush()

            segment = record_cls(file=audio_file.name)

            with (
                mock.patch.object(
                    audio_sender.asyncio,
                    "create_subprocess_exec",
                    new=mock.AsyncMock(return_value=FakeProcess()),
                ),
                mock.patch.object(audio_sender, "send_content", new=fake_send_content),
            ):
                await audio_sender.send_audio(
                    client=FakeClient(),
                    segment=segment,
                    room_id="!room:example.org",
                    reply_to=None,
                    thread_root=None,
                    use_thread=False,
                    is_encrypted_room=False,
                    e2ee_manager=None,
                    upload_size_limit=1024 * 1024,
                )

        self.assertEqual(captured["msg_type"], "m.room.message")
        self.assertEqual(captured["content"]["msgtype"], "m.audio")
        self.assertEqual(captured["content"]["org.matrix.msc3245.voice"], {})
        self.assertEqual(
            captured["content"]["org.matrix.msc1767.audio"], {"duration": 1234}
        )
        self.assertEqual(captured["content"]["info"]["duration"], 1234)

    async def test_audio_handler_accepts_voice_and_extensible_file_fallback(self):
        audio_handler = load_module("receiver.handlers.audio")

        size_calls = []

        def _is_media_over_auto_download_limit(size_bytes):
            size_calls.append(size_bytes)
            return False

        receiver = types.SimpleNamespace(
            client=None,
            mxc_converter=lambda mxc: "https://cdn.example.org/voice.ogg",
            _extract_media_size=lambda content: None,
            _is_media_over_auto_download_limit=_is_media_over_auto_download_limit,
            _should_auto_download_media=lambda msgtype: True,
        )
        chain = types.SimpleNamespace(chain=[])
        event = types.SimpleNamespace(
            body="Voice message",
            content={
                "org.matrix.msc3245.voice": {},
                "org.matrix.msc1767.audio": {"duration": 2817},
                "org.matrix.msc1767.file": {
                    "url": "mxc://example.org/voice",
                    "name": "Voice message.ogg",
                    "mimetype": "audio/ogg",
                    "size": 3385,
                },
            },
        )

        await audio_handler.handle_audio(receiver, chain, event, "m.audio")

        self.assertEqual(size_calls, [3385])
        self.assertEqual(chain.chain[0].url, "https://cdn.example.org/voice.ogg")


class MatrixThreadCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_content_marks_thread_messages_as_fallback(self):
        common_sender = load_module("sender.handlers.common")

        class FakeClient:
            async def send_message(self, **kwargs):
                return kwargs

        response = await common_sender.send_content(
            client=FakeClient(),
            content={"msgtype": "m.text", "body": "hello"},
            room_id="!room:example.org",
            reply_to=None,
            thread_root="$root:example.org",
            use_thread=True,
            is_encrypted_room=False,
            e2ee_manager=None,
        )

        self.assertEqual(
            response["content"]["m.relates_to"],
            {
                "rel_type": "m.thread",
                "event_id": "$root:example.org",
                "m.in_reply_to": {"event_id": "$root:example.org"},
                "is_falling_back": True,
            },
        )

    async def test_send_content_prefers_explicit_reply_for_thread_context(self):
        common_sender = load_module("sender.handlers.common")

        class FakeClient:
            async def send_message(self, **kwargs):
                return kwargs

        response = await common_sender.send_content(
            client=FakeClient(),
            content={"msgtype": "m.text", "body": "hello"},
            room_id="!room:example.org",
            reply_to="$reply:example.org",
            thread_root="$root:example.org",
            use_thread=True,
            is_encrypted_room=False,
            e2ee_manager=None,
        )

        self.assertEqual(
            response["content"]["m.relates_to"],
            {
                "rel_type": "m.thread",
                "event_id": "$root:example.org",
                "m.in_reply_to": {"event_id": "$reply:example.org"},
                "is_falling_back": True,
            },
        )

    async def test_send_plain_skips_legacy_reply_fallback_for_thread_messages(self):
        module_name = f"{PACKAGE_NAME}.sender.handlers.plain"
        markdown_utils_name = f"{PACKAGE_NAME}.utils.markdown_utils"
        sys.modules.pop(module_name, None)
        sys.modules.pop(markdown_utils_name, None)

        bleach_stub = types.ModuleType("bleach")
        bleach_stub.clean = lambda html, **kwargs: html

        markdown_it_stub = types.ModuleType("markdown_it")

        class _MarkdownIt:
            def __init__(self, *args, **kwargs):
                pass

            def render(self, text):
                return text

        markdown_it_stub.MarkdownIt = _MarkdownIt

        with mock.patch.dict(
            sys.modules,
            {"bleach": bleach_stub, "markdown_it": markdown_it_stub},
        ):
            plain_sender = load_module("sender.handlers.plain")
        plain_cls = sys.modules["astrbot.api.message_components"].Plain
        captured = {}

        async def fake_send_content(
            client,
            content,
            room_id,
            reply_to,
            thread_root,
            use_thread,
            is_encrypted_room,
            e2ee_manager,
            msg_type="m.room.message",
        ):
            captured["content"] = content
            captured["reply_to"] = reply_to
            captured["thread_root"] = thread_root
            captured["use_thread"] = use_thread
            return {"event_id": "$thread"}

        with mock.patch.object(plain_sender, "send_content", new=fake_send_content):
            await plain_sender.send_plain(
                client=object(),
                segment=plain_cls("thread"),
                room_id="!room:example.org",
                reply_to="$root:example.org",
                thread_root="$root:example.org",
                use_thread=True,
                original_message_info={
                    "sender": "@alice:example.org",
                    "body": "quoted text",
                },
                is_encrypted_room=False,
                e2ee_manager=None,
                use_notice=False,
            )

        self.assertEqual(captured["content"]["body"], "thread")
        self.assertEqual(captured["content"]["format"], "org.matrix.custom.html")
        self.assertEqual(captured["content"]["formatted_body"], "thread")
        self.assertNotIn("> <@alice:example.org>", captured["content"]["body"])
        self.assertNotIn("mx-reply", captured["content"]["formatted_body"])


class MatrixOAuth2CompatTests(unittest.IsolatedAsyncioTestCase):
    def test_oauth2_normalizes_legacy_scopes_to_stable(self):
        oauth2_module = load_module("auth.oauth2")

        handler = oauth2_module.MatrixOAuth2(
            client=object(),
            homeserver="https://example.org",
            scopes=[
                "openid",
                "urn:matrix:org.matrix.msc2967.client:api:*",
                "urn:matrix:org.matrix.msc2967.client:device:LEGACYDEVICE",
            ],
        )

        self.assertIn("urn:matrix:client:api:*", handler.scopes)
        self.assertNotIn(
            "urn:matrix:org.matrix.msc2967.client:api:*",
            handler.scopes,
        )
        self.assertIn("urn:matrix:client:device:LEGACYDEVICE", handler.scopes)
        self.assertEqual(handler.device_id, "LEGACYDEVICE")

    async def test_discovery_prefers_auth_metadata(self):
        discovery_module = load_module("auth.oauth2_discovery")

        class DummyDiscovery(discovery_module.MatrixOAuth2Discovery):
            def __init__(self):
                self.homeserver = "https://example.org"
                self.issuer = None
                self.authorization_endpoint = None
                self.token_endpoint = None
                self.registration_endpoint = None
                self.account_management_uri = None

        class FakeResponse:
            def __init__(self, status, payload):
                self.status = status
                self._payload = payload

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def json(self):
                return self._payload

            async def text(self):
                return str(self._payload)

        class FakeSession:
            def __init__(self, routes, calls, *args, **kwargs):
                self.routes = routes
                self.calls = calls

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            def get(self, url):
                self.calls.append(url)
                status, payload = self.routes[url]
                return FakeResponse(status, payload)

        auth_metadata_url = "https://example.org/_matrix/client/v1/auth_metadata"
        calls = []
        routes = {
            auth_metadata_url: (
                200,
                {
                    "issuer": "https://issuer.example.org",
                    "authorization_endpoint": "https://issuer.example.org/auth",
                    "token_endpoint": "https://issuer.example.org/token",
                },
            )
        }

        with mock.patch.object(
            discovery_module.aiohttp,
            "ClientSession",
            side_effect=lambda timeout=None: FakeSession(routes, calls),
        ):
            result = await DummyDiscovery()._discover_oauth_endpoints()

        self.assertEqual(calls, [auth_metadata_url])
        self.assertEqual(
            result["authorization_endpoint"],
            "https://issuer.example.org/auth",
        )


class MatrixDehydratedDeviceCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_restore_skips_dehydrated_when_local_recovery_key_is_valid(self):
        ssss_module = load_module("e2ee.key_backup_ssss")

        expected_key = b"L" * 32

        class DummyBackup(ssss_module.KeyBackupSSSSMixin):
            def __init__(self):
                self._recovery_key_bytes = expected_key
                self.get_dehydrated_calls = 0
                self.read_secret_calls = 0

            def _verify_recovery_key(self, key, log_mismatch=True):
                return key == expected_key

            async def _get_dehydrated_device(self):
                self.get_dehydrated_calls += 1
                return {"should": "not-be-read"}

            async def read_secret_from_secret_storage(self, secret_name, key_bytes=None):
                self.read_secret_calls += 1
                return b"should-not-be-read"

        backup = DummyBackup()

        restored_key = await backup._try_restore_from_secret_storage(b"provided-key")

        self.assertEqual(restored_key, expected_key)
        self.assertEqual(backup.get_dehydrated_calls, 0)
        self.assertEqual(backup.read_secret_calls, 0)

    async def test_restore_supports_legacy_secret_name_without_default_key(self):
        constants = load_module("constants")
        ssss_module = load_module("e2ee.key_backup_ssss")
        crypto_module = load_module("e2ee.key_backup_crypto")

        expected_key = b"K" * 32
        encoded_key = crypto_module._encode_recovery_key(expected_key)

        class FakeClient:
            def __init__(self):
                self.calls = []

            async def get_global_account_data(self, key):
                self.calls.append(key)
                if key == constants.DEHYDRATED_DEVICE_EVENT:
                    return None
                if key == constants.MSC2697_DEHYDRATED_DEVICE_EVENT:
                    return {"device_data": {"ciphertext": "x", "iv": "y", "mac": "z"}}
                return None

        class DummyBackup(ssss_module.KeyBackupSSSSMixin):
            def __init__(self, client):
                self.client = client
                self.secret_names = []

            def _decrypt_ssss_data(self, key, encrypted_data, secret_name=""):
                self.secret_names.append(secret_name)
                if secret_name == constants.MSC2697_DEHYDRATED_DEVICE_EVENT:
                    payload = {"m.megolm_backup.v1": encoded_key}
                    return str(payload).replace("'", '"').encode("utf-8")
                return None

        client = FakeClient()
        backup = DummyBackup(client)

        restored_key = await backup._try_restore_from_secret_storage(b"provided-key")

        self.assertEqual(restored_key, expected_key)
        self.assertEqual(
            client.calls,
            [
                constants.DEHYDRATED_DEVICE_EVENT,
                constants.MSC2697_DEHYDRATED_DEVICE_EVENT,
            ],
        )

    async def test_secret_storage_roundtrip_bootstraps_default_key(self):
        constants = load_module("constants")
        ssss_module = load_module("e2ee.key_backup_ssss")

        if not getattr(ssss_module, "CRYPTO_AVAILABLE", False):
            self.skipTest("cryptography unavailable")

        class FakeClient:
            def __init__(self):
                self.account_data = {}

            async def get_global_account_data(self, key):
                value = self.account_data.get(key)
                return dict(value) if isinstance(value, dict) else value

            async def set_global_account_data(self, key, value):
                self.account_data[key] = dict(value)
                return {}

        class DummyBackup(ssss_module.KeyBackupSSSSMixin):
            def __init__(self, client):
                self.client = client
                self._provided_secret_storage_key_bytes = b"K" * 32

        client = FakeClient()
        backup = DummyBackup(client)
        secret_payload = base64.b64encode(b"cross-signing-master").decode("utf-8")

        ok = await backup.write_secret_to_secret_storage(
            constants.SECRET_CROSS_SIGNING_MASTER,
            secret_payload,
        )
        self.assertTrue(ok)

        default_key = client.account_data[constants.SSSS_DEFAULT_KEY]["key"]
        self.assertTrue(default_key.startswith("ssss_"))
        self.assertIn(
            f"{constants.SSSS_KEY_PREFIX}{default_key}",
            client.account_data,
        )
        self.assertIn(
            default_key,
            client.account_data[constants.SECRET_CROSS_SIGNING_MASTER]["encrypted"],
        )

        restored = await backup.read_secret_from_secret_storage(
            constants.SECRET_CROSS_SIGNING_MASTER
        )
        self.assertEqual(restored, secret_payload.encode("utf-8"))


class MatrixAuthCompatTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _load_auth_module():
        _install_astrbot_stubs()
        _install_aiohttp_stub()
        _install_package_stubs()

        def _make_module(name: str, **attrs):
            module = types.ModuleType(name)
            for key, value in attrs.items():
                setattr(module, key, value)
            return module

        stubs = {
            f"{PACKAGE_NAME}.plugin_config": _make_module(
                f"{PACKAGE_NAME}.plugin_config",
                get_plugin_config=lambda: types.SimpleNamespace(
                    storage_backend_config=types.SimpleNamespace(
                        backend="json",
                        pgsql_dsn="",
                        pgsql_schema="public",
                        pgsql_table_prefix="matrix_store",
                    )
                ),
            ),
            f"{PACKAGE_NAME}.utils": _make_module(
                f"{PACKAGE_NAME}.utils",
                parse_bool=lambda value, default=False: default,
            ),
        }

        with mock.patch.dict(sys.modules, stubs):
            return importlib.import_module(f"{PACKAGE_NAME}.auth.auth")

    async def test_qr_mode_reuses_persisted_token_before_reprompting(self):
        auth_module = self._load_auth_module()

        config = types.SimpleNamespace(
            user_id="@alice:example.org",
            password="",
            access_token="",
            auth_method="qr",
            device_name="AstrBot",
            refresh_token="",
            device_id="DEV123",
            homeserver="https://matrix.example.org",
            store_path=tempfile.gettempdir(),
        )
        auth = auth_module.MatrixAuth(client=object(), config=config)

        events = []

        def fake_load_token():
            auth.access_token = "persisted-token"
            events.append("load")
            return True

        async def fake_login_via_token():
            events.append("token")

        async def fake_login_via_qr():
            events.append("qr")

        auth._load_token = fake_load_token
        auth._login_via_token = fake_login_via_token
        auth._login_via_qr = fake_login_via_qr

        await auth.login()

        self.assertEqual(events, ["load", "token"])

    async def test_qr_mode_falls_back_to_qr_when_persisted_token_is_invalid(self):
        auth_module = self._load_auth_module()

        config = types.SimpleNamespace(
            user_id="@alice:example.org",
            password="",
            access_token="",
            auth_method="qr",
            device_name="AstrBot",
            refresh_token="",
            device_id="DEV123",
            homeserver="https://matrix.example.org",
            store_path=tempfile.gettempdir(),
        )
        auth = auth_module.MatrixAuth(client=object(), config=config)

        events = []

        def fake_load_token():
            auth.access_token = "persisted-token"
            events.append("load")
            return True

        async def fake_login_via_token():
            events.append("token")
            raise RuntimeError("expired")

        async def fake_login_via_qr():
            events.append("qr")

        auth._load_token = fake_load_token
        auth._login_via_token = fake_login_via_token
        auth._login_via_qr = fake_login_via_qr

        await auth.login()

        self.assertEqual(events, ["load", "token", "qr"])


class MatrixDeviceKeyCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_restored_account_reuploads_device_keys_when_server_missing_device(self):
        keys_module = load_module("e2ee.e2ee_manager_keys")

        class DummyClient:
            def __init__(self):
                self.upload_calls = []
                self.query_calls = []

            async def upload_keys(self, device_keys=None, one_time_keys=None, fallback_keys=None):
                self.upload_calls.append(
                    {
                        "device_keys": device_keys,
                        "one_time_keys": one_time_keys,
                        "fallback_keys": fallback_keys,
                    }
                )
                return {"one_time_key_counts": {"signed_curve25519": 50}}

            async def query_keys(self, device_keys, timeout=10000):
                self.query_calls.append(device_keys)
                return {"device_keys": {"@alice:example.org": {}}}

        class DummyOlm:
            is_new_account = False

            def __init__(self):
                self.marked = False

            def get_device_keys(self):
                return {
                    "user_id": "@alice:example.org",
                    "device_id": "DEV123",
                    "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                    "keys": {
                        "curve25519:DEV123": "curve",
                        "ed25519:DEV123": "ed",
                    },
                    "signatures": {"@alice:example.org": {"ed25519:DEV123": "sig"}},
                }

            def generate_one_time_keys(self, count):
                return {}

            def get_unpublished_fallback_key_count(self):
                return 1

            def mark_keys_as_published(self):
                self.marked = True

        class DummyManager(keys_module.E2EEManagerKeysMixin):
            def __init__(self):
                self._olm = DummyOlm()
                self.client = DummyClient()
                self.user_id = "@alice:example.org"
                self.device_id = "DEV123"

            async def _get_server_key_counts(self):
                return {"signed_curve25519": 50}

        manager = DummyManager()
        await manager._upload_device_keys()

        self.assertEqual(manager.client.query_calls, [{"@alice:example.org": []}, {"@alice:example.org": []}])
        self.assertEqual(len(manager.client.upload_calls), 1)
        self.assertIsNotNone(manager.client.upload_calls[0]["device_keys"])
        self.assertTrue(manager._olm.marked)

    async def test_restored_account_skips_device_key_upload_when_server_has_device(self):
        keys_module = load_module("e2ee.e2ee_manager_keys")

        class DummyClient:
            def __init__(self):
                self.upload_calls = []
                self.query_calls = []

            async def upload_keys(self, device_keys=None, one_time_keys=None, fallback_keys=None):
                self.upload_calls.append(
                    {
                        "device_keys": device_keys,
                        "one_time_keys": one_time_keys,
                        "fallback_keys": fallback_keys,
                    }
                )
                return {"one_time_key_counts": {"signed_curve25519": 50}}

            async def query_keys(self, device_keys, timeout=10000):
                self.query_calls.append(device_keys)
                return {
                    "device_keys": {
                        "@alice:example.org": {
                            "DEV123": {
                                "keys": {
                                    "curve25519:DEV123": "curve",
                                    "ed25519:DEV123": "ed",
                                }
                            }
                        }
                    }
                }

        class DummyOlm:
            is_new_account = False

            def __init__(self):
                self.marked = False

            def get_device_keys(self):
                raise AssertionError("should not build device keys when already present")

            def get_identity_keys(self):
                return {
                    "curve25519:DEV123": "curve",
                    "ed25519:DEV123": "ed",
                }

            def generate_one_time_keys(self, count):
                return {}

            def get_unpublished_fallback_key_count(self):
                return 1

            def mark_keys_as_published(self):
                self.marked = True

        class DummyManager(keys_module.E2EEManagerKeysMixin):
            def __init__(self):
                self._olm = DummyOlm()
                self.client = DummyClient()
                self.user_id = "@alice:example.org"
                self.device_id = "DEV123"

            async def _get_server_key_counts(self):
                return {"signed_curve25519": 50}

        manager = DummyManager()
        await manager._upload_device_keys()

        self.assertEqual(manager.client.query_calls, [{"@alice:example.org": []}])
        self.assertEqual(manager.client.upload_calls, [])
        self.assertFalse(manager._olm.marked)

    async def test_restored_account_reuploads_device_keys_when_server_keys_mismatch(self):
        keys_module = load_module("e2ee.e2ee_manager_keys")

        class DummyClient:
            def __init__(self):
                self.upload_calls = []
                self.query_calls = []

            async def upload_keys(self, device_keys=None, one_time_keys=None, fallback_keys=None):
                self.upload_calls.append(
                    {
                        "device_keys": device_keys,
                        "one_time_keys": one_time_keys,
                        "fallback_keys": fallback_keys,
                    }
                )
                return {"one_time_key_counts": {"signed_curve25519": 50}}

            async def query_keys(self, device_keys, timeout=10000):
                self.query_calls.append(device_keys)
                if len(self.query_calls) == 1:
                    return {
                        "device_keys": {
                            "@alice:example.org": {
                                "DEV123": {
                                    "keys": {
                                        "curve25519:DEV123": "server-curve",
                                        "ed25519:DEV123": "server-ed",
                                    }
                                }
                            }
                        }
                    }
                return {
                    "device_keys": {
                        "@alice:example.org": {
                            "DEV123": {
                                "keys": {
                                    "curve25519:DEV123": "local-curve",
                                    "ed25519:DEV123": "local-ed",
                                }
                            }
                        }
                    }
                }

        class DummyOlm:
            is_new_account = False

            def __init__(self):
                self.marked = False

            def get_device_keys(self):
                return {
                    "user_id": "@alice:example.org",
                    "device_id": "DEV123",
                    "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
                    "keys": {
                        "curve25519:DEV123": "local-curve",
                        "ed25519:DEV123": "local-ed",
                    },
                    "signatures": {"@alice:example.org": {"ed25519:DEV123": "sig"}},
                }

            def get_identity_keys(self):
                return {
                    "curve25519:DEV123": "local-curve",
                    "ed25519:DEV123": "local-ed",
                }

            def generate_one_time_keys(self, count):
                return {}

            def get_unpublished_fallback_key_count(self):
                return 1

            def mark_keys_as_published(self):
                self.marked = True

        class DummyManager(keys_module.E2EEManagerKeysMixin):
            def __init__(self):
                self._olm = DummyOlm()
                self.client = DummyClient()
                self.user_id = "@alice:example.org"
                self.device_id = "DEV123"

            async def _get_server_key_counts(self):
                return {"signed_curve25519": 50}

        manager = DummyManager()
        await manager._upload_device_keys()

        self.assertEqual(manager.client.query_calls, [{"@alice:example.org": []}, {"@alice:example.org": []}])
        self.assertEqual(len(manager.client.upload_calls), 1)
        self.assertIsNotNone(manager.client.upload_calls[0]["device_keys"])
        self.assertTrue(manager._olm.marked)


class MatrixVerificationCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_verification_request_caches_fingerprint_for_done_stage(self):
        flow_module = load_module("e2ee.verification_handlers_flow")

        class DummyClient:
            async def query_keys(self, device_keys, timeout=10000):
                return {
                    "device_keys": {
                        "@alice:example.org": {
                            "DEV123": {
                                "keys": {"ed25519:DEV123": "fingerprint-ed25519"}
                            }
                        }
                    }
                }

        class DummyVerifier(flow_module.SASVerificationFlowMixin):
            def __init__(self):
                self.client = DummyClient()
                self._sessions = {}
                self.auto_verify_mode = "auto_reject"
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"

            async def _send_cancel(self, *args, **kwargs):
                return None

        verifier = DummyVerifier()
        await verifier._handle_request(
            "@alice:example.org",
            {
                "from_device": "DEV123",
                "methods": ["m.sas.v1"],
            },
            "txn123",
        )

        self.assertEqual(
            verifier._sessions["txn123"].get("fingerprint"),
            "fingerprint-ed25519",
        )

    async def test_handle_done_publishes_cross_signing_for_same_user_devices(self):
        flow_module = load_module("e2ee.verification_handlers_flow")

        class DummyDeviceStore:
            def __init__(self):
                self.calls = []

            def add_device(self, user_id, device_id, fingerprint):
                self.calls.append((user_id, device_id, fingerprint))

        class DummyManager:
            def __init__(self):
                self.calls = []

            async def publish_trusted_device(self, user_id, device_id):
                self.calls.append((user_id, device_id))
                return True

        class DummyVerifier(flow_module.SASVerificationFlowMixin):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self._sessions = {
                    "txn123": {
                        "from_device": "DEV456",
                        "fingerprint": "fp456",
                        "mac_verified": True,
                    }
                }
                self.device_store = DummyDeviceStore()
                self.e2ee_manager = DummyManager()

        verifier = DummyVerifier()
        await verifier._handle_done("@bot:example.org", {}, "txn123")

        self.assertEqual(
            verifier.device_store.calls,
            [("@bot:example.org", "DEV456", "fp456")],
        )
        self.assertEqual(
            verifier.e2ee_manager.calls,
            [
                ("@bot:example.org", "DEV456"),
                ("@bot:example.org", "BOT123"),
            ],
        )

    async def test_handle_done_does_not_publish_cross_signing_for_other_users(self):
        flow_module = load_module("e2ee.verification_handlers_flow")

        class DummyDeviceStore:
            def __init__(self):
                self.calls = []

            def add_device(self, user_id, device_id, fingerprint):
                self.calls.append((user_id, device_id, fingerprint))

        class DummyManager:
            def __init__(self):
                self.calls = []

            async def publish_trusted_device(self, user_id, device_id):
                self.calls.append((user_id, device_id))
                return True

        class DummyVerifier(flow_module.SASVerificationFlowMixin):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self._sessions = {
                    "txn123": {
                        "from_device": "ALICE1",
                        "fingerprint": "alice-fp",
                        "mac_verified": True,
                    }
                }
                self.device_store = DummyDeviceStore()
                self.e2ee_manager = DummyManager()

        verifier = DummyVerifier()
        await verifier._handle_done("@alice:example.org", {}, "txn123")

        self.assertEqual(
            verifier.device_store.calls,
            [("@alice:example.org", "ALICE1", "alice-fp")],
        )
        self.assertEqual(verifier.e2ee_manager.calls, [])

    async def test_publish_trusted_device_requires_same_user_and_self_signing_key(self):
        verification_module = load_module("e2ee.e2ee_manager_verification")

        class DummyCrossSigning:
            def __init__(self, has_key=True, master_ok=True):
                self.self_signing_private_key = b"key" if has_key else None
                self.device_calls = []
                self.master_calls = []
                self.master_ok = master_ok

            async def sign_device(self, device_id):
                self.device_calls.append(device_id)
                return True

            async def sign_master_key_with_device(self, user_id):
                self.master_calls.append(user_id)
                return self.master_ok

        class DummyManager(verification_module.E2EEManagerVerificationMixin):
            def __init__(self, cross_signing):
                self.user_id = "@bot:example.org"
                self._cross_signing = cross_signing

        manager = DummyManager(DummyCrossSigning())
        ok = await manager.publish_trusted_device("@bot:example.org", "BOT123")
        self.assertTrue(ok)
        self.assertEqual(manager._cross_signing.device_calls, ["BOT123"])
        self.assertEqual(manager._cross_signing.master_calls, ["@bot:example.org"])

        other_user_ok = await manager.publish_trusted_device(
            "@alice:example.org", "ALICE1"
        )
        self.assertFalse(other_user_ok)
        self.assertEqual(manager._cross_signing.device_calls, ["BOT123"])

        no_key_manager = DummyManager(DummyCrossSigning(has_key=False))
        no_key_ok = await no_key_manager.publish_trusted_device(
            "@bot:example.org", "BOT123"
        )
        self.assertFalse(no_key_ok)
        self.assertEqual(no_key_manager._cross_signing.device_calls, [])

        master_fail_manager = DummyManager(DummyCrossSigning(master_ok=False))
        master_fail_ok = await master_fail_manager.publish_trusted_device(
            "@bot:example.org", "BOT123"
        )
        self.assertFalse(master_fail_ok)
        self.assertEqual(master_fail_manager._cross_signing.device_calls, ["BOT123"])
        self.assertEqual(
            master_fail_manager._cross_signing.master_calls,
            ["@bot:example.org"],
        )

    async def test_self_signing_secret_persists_and_retries_signing_own_device(self):
        secrets_module = load_module("e2ee.e2ee_manager_secrets")
        constants = load_module("constants")

        class DummyCrossSigning:
            def __init__(self):
                self.self_signing_private_key = None
                self.persist_calls = 0

            def persist_local_keys(self):
                self.persist_calls += 1

        class DummyManager(secrets_module.E2EEManagerSecretsMixin):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self._cross_signing = DummyCrossSigning()
                self.calls = []
                self._key_backup = None

            async def publish_trusted_device(self, user_id, device_id):
                self.calls.append((user_id, device_id))
                return True

        manager = DummyManager()
        encoded = base64.b64encode(b"self-signing-secret").decode("utf-8")

        await manager._process_received_secret(
            constants.SECRET_CROSS_SIGNING_SELF_SIGNING,
            encoded,
        )

        self.assertEqual(
            manager._cross_signing.self_signing_private_key,
            b"self-signing-secret",
        )
        self.assertEqual(manager._cross_signing.persist_calls, 1)
        self.assertEqual(manager.calls, [("@bot:example.org", "BOT123")])

    async def test_send_mac_includes_device_and_master_key(self):
        send_module = load_module("e2ee.verification_send_device")

        class DummyEstablishedSas:
            def calculate_mac(self, message, info):
                return f"mac::{message}::{info}"

        class DummyVerifier(send_module.SASVerificationSendDeviceMixin):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self.olm = types.SimpleNamespace(ed25519_key="device-ed25519")
                self.e2ee_manager = types.SimpleNamespace(
                    _cross_signing=types.SimpleNamespace(master_key="MASTERKEY")
                )
                self.sent = []

            async def _send_to_device(self, event_type, to_user, to_device, content):
                self.sent.append((event_type, to_user, to_device, content))

        verifier = DummyVerifier()
        session = {"established_sas": DummyEstablishedSas()}

        await verifier._send_mac("@alice:example.org", "DEV456", "txn123", session)

        self.assertEqual(len(verifier.sent), 1)
        event_type, to_user, to_device, content = verifier.sent[0]
        self.assertEqual(event_type, "m.key.verification.mac")
        self.assertEqual((to_user, to_device), ("@alice:example.org", "DEV456"))

        device_key_id = "ed25519:BOT123"
        master_key_id = "ed25519:MASTERKEY"
        base_info = "MATRIX_KEY_VERIFICATION_MAC@bot:example.orgBOT123@alice:example.orgDEV456txn123"
        key_ids_csv = ",".join(sorted([device_key_id, master_key_id]))

        self.assertEqual(
            content,
            {
                "transaction_id": "txn123",
                "mac": {
                    device_key_id: f"mac::device-ed25519::{base_info}{device_key_id}",
                    master_key_id: f"mac::MASTERKEY::{base_info}{master_key_id}",
                },
                "keys": f"mac::{key_ids_csv}::{base_info}KEY_IDS",
            },
        )

    async def test_send_in_room_mac_includes_device_and_master_key(self):
        send_module = load_module("e2ee.verification_send_device")
        room_module = load_module("e2ee.verification_send_room")

        class DummyEstablishedSas:
            def calculate_mac(self, message, info):
                return f"mac::{message}::{info}"

        class DummyVerifier(
            send_module.SASVerificationSendDeviceMixin,
            room_module.SASVerificationSendRoomMixin,
        ):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self.olm = types.SimpleNamespace(ed25519_key="device-ed25519")
                self.e2ee_manager = types.SimpleNamespace(
                    _cross_signing=types.SimpleNamespace(master_key="MASTERKEY")
                )
                self.sent = []

            async def _send_in_room_event(
                self, room_id, event_type, content, transaction_id
            ):
                self.sent.append((room_id, event_type, content, transaction_id))

        verifier = DummyVerifier()
        session = {
            "established_sas": DummyEstablishedSas(),
            "sender": "@alice:example.org",
            "from_device": "DEV456",
        }

        await verifier._send_in_room_mac("!room:example.org", "txn123", session)

        self.assertEqual(len(verifier.sent), 1)
        room_id, event_type, content, transaction_id = verifier.sent[0]
        self.assertEqual(room_id, "!room:example.org")
        self.assertEqual(event_type, "m.key.verification.mac")
        self.assertEqual(transaction_id, "txn123")

        device_key_id = "ed25519:BOT123"
        master_key_id = "ed25519:MASTERKEY"
        base_info = "MATRIX_KEY_VERIFICATION_MAC@bot:example.orgBOT123@alice:example.orgDEV456txn123"
        key_ids_csv = ",".join(sorted([device_key_id, master_key_id]))

        self.assertEqual(
            content,
            {
                "mac": {
                    device_key_id: f"mac::device-ed25519::{base_info}{device_key_id}",
                    master_key_id: f"mac::MASTERKEY::{base_info}{master_key_id}",
                },
                "keys": f"mac::{key_ids_csv}::{base_info}KEY_IDS",
            },
        )

    async def test_handle_mac_sends_done_only_after_successful_verification(self):
        flow_module = load_module("e2ee.verification_handlers_flow")

        class DummyEstablishedSas:
            def calculate_mac(self, message, info):
                return f"mac::{message}::{info}"

        class DummyVerifier(flow_module.SASVerificationFlowMixin):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self.auto_verify_mode = "auto_accept"
                self._sessions = {
                    "txn123": {
                        "from_device": "DEV456",
                        "their_device": "DEV456",
                        "fingerprint": "fingerprint-ed25519",
                        "master_key_id": "ed25519:MASTERKEY",
                        "master_key": "master-key-base64",
                        "established_sas": DummyEstablishedSas(),
                    }
                }
                self.done_calls = []
                self.cancel_calls = []

            async def _send_done(self, sender, device_id, transaction_id):
                self.done_calls.append((sender, device_id, transaction_id))

            async def _send_cancel(self, sender, device_id, transaction_id, code, reason):
                self.cancel_calls.append((sender, device_id, transaction_id, code, reason))

        verifier = DummyVerifier()
        device_key_id = "ed25519:DEV456"
        master_key_id = "ed25519:MASTERKEY"
        base_info = "MATRIX_KEY_VERIFICATION_MAC@alice:example.orgDEV456@bot:example.orgBOT123txn123"
        key_ids_csv = ",".join(sorted([device_key_id, master_key_id]))
        await verifier._handle_mac(
            "@alice:example.org",
            {
                "mac": {
                    device_key_id: f"mac::fingerprint-ed25519::{base_info}{device_key_id}",
                    master_key_id: f"mac::master-key-base64::{base_info}{master_key_id}",
                },
                "keys": f"mac::{key_ids_csv}::{base_info}KEY_IDS",
            },
            "txn123",
        )

        self.assertEqual(
            verifier.done_calls,
            [("@alice:example.org", "DEV456", "txn123")],
        )
        self.assertEqual(verifier.cancel_calls, [])
        self.assertTrue(verifier._sessions["txn123"].get("mac_verified"))

    async def test_handle_mac_cancels_on_mismatched_mac(self):
        flow_module = load_module("e2ee.verification_handlers_flow")

        class DummyEstablishedSas:
            def calculate_mac(self, message, info):
                return f"mac::{message}::{info}"

        class DummyVerifier(flow_module.SASVerificationFlowMixin):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self.auto_verify_mode = "auto_accept"
                self._sessions = {
                    "txn123": {
                        "from_device": "DEV456",
                        "their_device": "DEV456",
                        "fingerprint": "fingerprint-ed25519",
                        "master_key_id": "ed25519:MASTERKEY",
                        "master_key": "master-key-base64",
                        "established_sas": DummyEstablishedSas(),
                    }
                }
                self.done_calls = []
                self.cancel_calls = []

            async def _send_done(self, sender, device_id, transaction_id):
                self.done_calls.append((sender, device_id, transaction_id))

            async def _send_cancel(self, sender, device_id, transaction_id, code, reason):
                self.cancel_calls.append((sender, device_id, transaction_id, code, reason))

        verifier = DummyVerifier()
        await verifier._handle_mac(
            "@alice:example.org",
            {
                "mac": {
                    "ed25519:DEV456": "wrong-mac",
                    "ed25519:MASTERKEY": "wrong-master-mac",
                },
                "keys": "wrong-keys",
            },
            "txn123",
        )

        self.assertEqual(verifier.done_calls, [])
        self.assertEqual(
            verifier.cancel_calls,
            [
                (
                    "@alice:example.org",
                    "DEV456",
                    "txn123",
                    "m.key_mismatch",
                    "MAC verification failed",
                )
            ],
        )
        self.assertFalse(verifier._sessions["txn123"].get("done_sent", False))

    async def test_handle_mac_cancels_when_fingerprint_missing(self):
        flow_module = load_module("e2ee.verification_handlers_flow")

        class DummyClient:
            async def query_keys(self, device_keys, timeout=10000):
                return {
                    "device_keys": {"@alice:example.org": {"DEV456": {"keys": {}}}},
                    "master_keys": {},
                }

        class DummyVerifier(flow_module.SASVerificationFlowMixin):
            def __init__(self):
                self.client = DummyClient()
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self.auto_verify_mode = "auto_accept"
                self._sessions = {
                    "txn123": {
                        "from_device": "DEV456",
                        "their_device": "DEV456",
                    }
                }
                self.done_calls = []
                self.cancel_calls = []

            async def _send_done(self, sender, device_id, transaction_id):
                self.done_calls.append((sender, device_id, transaction_id))

            async def _send_cancel(self, sender, device_id, transaction_id, code, reason):
                self.cancel_calls.append((sender, device_id, transaction_id, code, reason))

        verifier = DummyVerifier()
        await verifier._handle_mac(
            "@alice:example.org",
            {
                "mac": {"ed25519:DEV456": "whatever"},
                "keys": "whatever",
            },
            "txn123",
        )

        self.assertEqual(verifier.done_calls, [])
        self.assertEqual(
            verifier.cancel_calls,
            [
                (
                    "@alice:example.org",
                    "DEV456",
                    "txn123",
                    "m.key_mismatch",
                    "MAC verification failed",
                )
            ],
        )

    async def test_handle_done_ignores_cancelled_or_unverified_session(self):
        flow_module = load_module("e2ee.verification_handlers_flow")

        class DummyDeviceStore:
            def __init__(self):
                self.calls = []

            def add_device(self, user_id, device_id, fingerprint):
                self.calls.append((user_id, device_id, fingerprint))

        class DummyVerifier(flow_module.SASVerificationFlowMixin):
            def __init__(self):
                self.user_id = "@bot:example.org"
                self.device_id = "BOT123"
                self._sessions = {
                    "txn123": {
                        "from_device": "DEV456",
                        "fingerprint": "fp456",
                        "state": "cancelled",
                    }
                }
                self.device_store = DummyDeviceStore()

        verifier = DummyVerifier()
        await verifier._handle_done("@bot:example.org", {}, "txn123")
        self.assertEqual(verifier.device_store.calls, [])


class MatrixCrossSigningCompatTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _load_cross_signing_module():
        _install_astrbot_stubs()
        _install_aiohttp_stub()
        _install_package_stubs()

        def _make_module(name: str, **attrs):
            module = types.ModuleType(name)
            for key, value in attrs.items():
                setattr(module, key, value)
            return module

        class DummyMatrixAPIError(Exception):
            def __init__(self, status=400, data=None, message="Matrix API Error"):
                self.status = status
                self.data = data or {}
                self.message = message
                super().__init__(message)

        stubs = {
            f"{PACKAGE_NAME}.plugin_config": _make_module(
                f"{PACKAGE_NAME}.plugin_config",
                get_plugin_config=lambda: types.SimpleNamespace(
                    storage_backend_config=types.SimpleNamespace(
                        backend="json",
                        pgsql_dsn="",
                        pgsql_schema="public",
                        pgsql_table_prefix="matrix_store",
                    )
                ),
            ),
            f"{PACKAGE_NAME}.client.http_client": _make_module(
                f"{PACKAGE_NAME}.client.http_client",
                MatrixAPIError=DummyMatrixAPIError,
            ),
            f"{PACKAGE_NAME}.e2ee.key_backup_crypto": _make_module(
                f"{PACKAGE_NAME}.e2ee.key_backup_crypto",
                CRYPTO_AVAILABLE=True,
            ),
            f"{PACKAGE_NAME}.e2ee.storage": _make_module(
                f"{PACKAGE_NAME}.e2ee.storage",
                build_e2ee_data_store=lambda **kwargs: types.SimpleNamespace(
                    get=lambda key: None,
                    upsert=lambda key, value: None,
                ),
            ),
        }

        module_name = f"{PACKAGE_NAME}.e2ee.cross_signing"
        sys.modules.pop(module_name, None)
        with mock.patch.dict(sys.modules, stubs):
            return importlib.import_module(module_name)

    async def test_sign_device_checks_failures_and_refreshed_signatures(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            def __init__(self):
                self.upload_payloads = []
                self.query_count = 0

            async def query_keys(self, device_keys, timeout=10000):
                self.query_count += 1
                if self.query_count <= 2:
                    return {
                        "device_keys": {
                            "@bot:example.org": {
                                "BOT123": {
                                    "keys": {
                                        "ed25519:BOT123": "device-ed25519",
                                        "curve25519:BOT123": "device-curve25519",
                                    },
                                    "signatures": {},
                                }
                            }
                        }
                    }
                return {
                    "device_keys": {
                        "@bot:example.org": {
                            "BOT123": {
                                "keys": {
                                    "ed25519:BOT123": "device-ed25519",
                                    "curve25519:BOT123": "device-curve25519",
                                },
                                "signatures": {
                                    "@bot:example.org": {
                                        "ed25519:SELFKEY": "sig",
                                    }
                                },
                            }
                        }
                    }
                }

            async def upload_signatures(self, signatures):
                self.upload_payloads.append(signatures)
                return {"failures": {}}

        class DummyOlm:
            class _Account:
                def sign(self, payload):
                    return types.SimpleNamespace(to_base64=lambda: "device-signature")

            def __init__(self):
                self._account = self._Account()

            def get_identity_keys(self):
                return {
                    "ed25519:BOT123": "device-ed25519",
                    "curve25519:BOT123": "device-curve25519",
                }

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
        )
        cross_signing._self_signing_priv = b"1" * 32
        cross_signing._self_signing_key = "SELFKEY"

        ok = await cross_signing.sign_device("BOT123")
        self.assertTrue(ok)
        self.assertEqual(len(cross_signing.client.upload_payloads), 1)

    async def test_sign_master_key_with_device_uploads_and_verifies_signature(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            def __init__(self):
                self.upload_payloads = []
                self.query_count = 0

            async def query_keys(self, device_keys, timeout=10000):
                self.query_count += 1
                if self.query_count <= 2:
                    return {
                        "device_keys": {
                            "@bot:example.org": {
                                "BOT123": {
                                    "keys": {
                                        "ed25519:BOT123": "device-ed25519",
                                        "curve25519:BOT123": "device-curve25519",
                                    }
                                }
                            }
                        },
                        "master_keys": {
                            "@bot:example.org": {
                                "user_id": "@bot:example.org",
                                "usage": ["master"],
                                "keys": {"ed25519:MASTERKEY": "MASTERKEY"},
                                "signatures": {
                                    "@bot:example.org": {
                                        "ed25519:OLD": "old-signature"
                                    }
                                },
                            }
                        }
                    }
                return {
                    "device_keys": {
                        "@bot:example.org": {
                            "BOT123": {
                                "keys": {
                                    "ed25519:BOT123": "device-ed25519",
                                    "curve25519:BOT123": "device-curve25519",
                                }
                            }
                        }
                    },
                    "master_keys": {
                        "@bot:example.org": {
                            "user_id": "@bot:example.org",
                            "usage": ["master"],
                            "keys": {"ed25519:MASTERKEY": "MASTERKEY"},
                            "signatures": {
                                "@bot:example.org": {
                                    "ed25519:OLD": "old-signature",
                                    "ed25519:BOT123": "device-signature"
                                }
                            },
                        }
                    }
                }

            async def upload_signatures(self, signatures):
                self.upload_payloads.append(signatures)
                return {"failures": {}}

        class DummyOlm:
            class _Account:
                def sign(self, payload):
                    return types.SimpleNamespace(to_base64=lambda: "device-signature")

            def __init__(self):
                self._account = self._Account()
                self.device_id = "BOT123"

            def get_identity_keys(self):
                return {
                    "ed25519:BOT123": "device-ed25519",
                    "curve25519:BOT123": "device-curve25519",
                }

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
        )
        cross_signing._master_key = "MASTERKEY"

        ok = await cross_signing.sign_master_key_with_device("@bot:example.org")
        self.assertTrue(ok)
        self.assertEqual(len(cross_signing.client.upload_payloads), 1)
        self.assertEqual(
            cross_signing.client.upload_payloads[0],
            {
                "@bot:example.org": {
                    "MASTERKEY": {
                        "user_id": "@bot:example.org",
                        "usage": ["master"],
                        "keys": {"ed25519:MASTERKEY": "MASTERKEY"},
                        "signatures": {
                            "@bot:example.org": {
                                "ed25519:BOT123": "device-signature"
                            }
                        },
                    }
                }
            },
        )

    async def test_sign_device_returns_false_when_server_reports_failures(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            async def query_keys(self, device_keys, timeout=10000):
                return {
                    "device_keys": {
                        "@bot:example.org": {
                            "BOT123": {
                                "keys": {
                                    "ed25519:BOT123": "device-ed25519",
                                    "curve25519:BOT123": "device-curve25519",
                                },
                                "signatures": {},
                            }
                        }
                    }
                }

            async def upload_signatures(self, signatures):
                return {
                    "failures": {
                        "@bot:example.org": {
                            "BOT123": {
                                "errcode": "M_INVALID_SIGNATURE",
                                "error": "Invalid signature",
                            }
                        }
                    }
                }

        class DummyOlm:
            class _Account:
                def sign(self, payload):
                    return types.SimpleNamespace(to_base64=lambda: "device-signature")

            def __init__(self):
                self._account = self._Account()

            def get_identity_keys(self):
                return {
                    "ed25519:BOT123": "device-ed25519",
                    "curve25519:BOT123": "device-curve25519",
                }

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
        )
        cross_signing._self_signing_priv = b"1" * 32
        cross_signing._self_signing_key = "SELFKEY"

        ok = await cross_signing.sign_device("BOT123")
        self.assertFalse(ok)

    async def test_sign_master_key_with_device_returns_false_when_current_device_keys_mismatch(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            def __init__(self):
                self.upload_payloads = []

            async def query_keys(self, device_keys, timeout=10000):
                return {
                    "device_keys": {
                        "@bot:example.org": {
                            "BOT123": {
                                "keys": {
                                    "ed25519:BOT123": "server-ed25519",
                                    "curve25519:BOT123": "server-curve25519",
                                }
                            }
                        }
                    },
                    "master_keys": {
                        "@bot:example.org": {
                            "user_id": "@bot:example.org",
                            "usage": ["master"],
                            "keys": {"ed25519:MASTERKEY": "MASTERKEY"},
                            "signatures": {
                                "@bot:example.org": {
                                    "ed25519:OLD": "old-signature"
                                }
                            },
                        }
                    },
                }

            async def upload_signatures(self, signatures):
                self.upload_payloads.append(signatures)
                return {"failures": {}}

        class DummyOlm:
            class _Account:
                def sign(self, payload):
                    return types.SimpleNamespace(to_base64=lambda: "device-signature")

            def __init__(self):
                self._account = self._Account()
                self.device_id = "BOT123"

            def get_identity_keys(self):
                return {
                    "ed25519:BOT123": "local-ed25519",
                    "curve25519:BOT123": "local-curve25519",
                }

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
        )
        cross_signing._master_key = "MASTERKEY"

        ok = await cross_signing.sign_master_key_with_device("@bot:example.org")
        self.assertFalse(ok)
        self.assertEqual(cross_signing.client.upload_payloads, [])

    async def test_initialize_restores_private_keys_from_ssss_before_overwrite(self):
        cross_signing_module = self._load_cross_signing_module()
        constants = load_module("constants")

        master_priv = b"m" * 32
        self_priv = b"s" * 32
        user_priv = b"u" * 32
        master_pub = "M" * 43
        self_pub = "S" * 43
        user_pub = "U" * 43

        class DummyClient:
            async def query_keys(self, device_keys, timeout=10000):
                return {
                    "master_keys": {
                        "@bot:example.org": {
                            "keys": {f"ed25519:{master_pub}": master_pub}
                        }
                    },
                    "self_signing_keys": {
                        "@bot:example.org": {
                            "keys": {f"ed25519:{self_pub}": self_pub}
                        }
                    },
                    "user_signing_keys": {
                        "@bot:example.org": {
                            "keys": {f"ed25519:{user_pub}": user_pub}
                        }
                    },
                }

        class DummySecretStorage:
            def __init__(self):
                self.payloads = {
                    constants.SECRET_CROSS_SIGNING_MASTER: base64.b64encode(master_priv).decode("utf-8").encode("utf-8"),
                    constants.SECRET_CROSS_SIGNING_SELF_SIGNING: base64.b64encode(self_priv).decode("utf-8").encode("utf-8"),
                    constants.SECRET_CROSS_SIGNING_USER_SIGNING: base64.b64encode(user_priv).decode("utf-8").encode("utf-8"),
                }

            async def read_ssss_secret(self, secret_name):
                return self.payloads.get(secret_name)

        class DummyOlm:
            def get_identity_keys(self):
                return {}

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
            secret_storage=DummySecretStorage(),
        )
        cross_signing._generate_and_upload_keys = mock.AsyncMock()
        cross_signing._derive_public_key = lambda priv: {
            master_priv: master_pub,
            self_priv: self_pub,
            user_priv: user_pub,
        }.get(priv)

        await cross_signing.initialize()

        self.assertEqual(cross_signing.master_private_key, master_priv)
        self.assertEqual(cross_signing.self_signing_private_key, self_priv)
        self.assertEqual(cross_signing.user_signing_private_key, user_priv)
        cross_signing._generate_and_upload_keys.assert_not_awaited()

    async def test_initialize_requests_device_secret_when_ssss_restore_fails(self):
        cross_signing_module = self._load_cross_signing_module()
        constants = load_module("constants")

        class DummyClient:
            async def query_keys(self, device_keys, timeout=10000):
                return {
                    "master_keys": {
                        "@bot:example.org": {
                            "keys": {f"ed25519:{'M' * 43}": "M" * 43}
                        }
                    },
                    "self_signing_keys": {
                        "@bot:example.org": {
                            "keys": {f"ed25519:{'S' * 43}": "S" * 43}
                        }
                    },
                    "user_signing_keys": {
                        "@bot:example.org": {
                            "keys": {f"ed25519:{'U' * 43}": "U" * 43}
                        }
                    },
                }

        class DummySecretStorage:
            async def read_ssss_secret(self, secret_name):
                return None

        request_mock = mock.AsyncMock(
            side_effect=["req-master", "req-self", "req-user"]
        )

        class DummyOlm:
            def get_identity_keys(self):
                return {}

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
            secret_storage=DummySecretStorage(),
            request_secret_from_devices=request_mock,
        )
        cross_signing._generate_and_upload_keys = mock.AsyncMock()

        await cross_signing.initialize()

        self.assertEqual(
            request_mock.await_args_list,
            [
                mock.call(constants.SECRET_CROSS_SIGNING_MASTER),
                mock.call(constants.SECRET_CROSS_SIGNING_SELF_SIGNING),
                mock.call(constants.SECRET_CROSS_SIGNING_USER_SIGNING),
            ],
        )
        cross_signing._generate_and_upload_keys.assert_not_awaited()

    async def test_generate_and_upload_keys_stores_private_keys_in_ssss_after_public_upload(self):
        cross_signing_module = self._load_cross_signing_module()
        constants = load_module("constants")

        class DummyClient:
            def __init__(self):
                self.calls = []

            async def upload_signing_keys(
                self,
                master_key=None,
                self_signing_key=None,
                user_signing_key=None,
                auth=None,
            ):
                self.calls.append(auth)
                return {}

        class DummySecretStorage:
            def __init__(self):
                self.calls = []

            async def write_ssss_secret(self, secret_name, secret_value):
                self.calls.append((secret_name, secret_value))
                return True

        class DummyOlm:
            def get_identity_keys(self):
                return {}

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
            secret_storage=DummySecretStorage(),
        )
        keypairs = iter(
            [
                (b"m" * 32, "MASTERKEY"),
                (b"s" * 32, "SELFKEY"),
                (b"u" * 32, "USERKEY"),
            ]
        )
        cross_signing._gen_keypair = lambda: next(keypairs)
        cross_signing._sign = lambda priv, payload: "sig"

        await cross_signing._generate_and_upload_keys(force_regen=True)

        self.assertEqual(cross_signing.client.calls, [None])
        self.assertEqual(
            cross_signing.secret_storage.calls,
            [
                (
                    constants.SECRET_CROSS_SIGNING_MASTER,
                    base64.b64encode(b"m" * 32).decode("utf-8"),
                ),
                (
                    constants.SECRET_CROSS_SIGNING_SELF_SIGNING,
                    base64.b64encode(b"s" * 32).decode("utf-8"),
                ),
                (
                    constants.SECRET_CROSS_SIGNING_USER_SIGNING,
                    base64.b64encode(b"u" * 32).decode("utf-8"),
                ),
            ],
        )

    async def test_generate_and_upload_keys_uses_uia_dummy_then_password(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            def __init__(self):
                self.auth_payloads = []
                self.calls = 0

            async def upload_signing_keys(
                self,
                master_key=None,
                self_signing_key=None,
                user_signing_key=None,
                auth=None,
            ):
                self.auth_payloads.append(auth)
                self.calls += 1
                if self.calls == 1:
                    raise cross_signing_module.MatrixAPIError(
                        401, {"session": "sess-1"}, "uia required"
                    )
                if self.calls == 2:
                    raise cross_signing_module.MatrixAPIError(
                        401, {"session": "sess-1"}, "dummy rejected"
                    )
                return {}

        class DummyOlm:
            def get_identity_keys(self):
                return {}

        cross_signing = cross_signing_module.CrossSigning(
            client=DummyClient(),
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
            password="secret-password",
        )
        keypairs = iter(
            [
                (b"m" * 32, "MASTERKEY"),
                (b"s" * 32, "SELFKEY"),
                (b"u" * 32, "USERKEY"),
            ]
        )
        cross_signing._gen_keypair = lambda: next(keypairs)
        cross_signing._sign = lambda priv, payload: "sig"

        await cross_signing._generate_and_upload_keys(force_regen=True)

        self.assertEqual(
            cross_signing.client.auth_payloads,
            [
                None,
                {"type": "m.login.dummy", "session": "sess-1"},
                {
                    "type": "m.login.password",
                    "identifier": {
                        "type": "m.id.user",
                        "user": "@bot:example.org",
                    },
                    "password": "secret-password",
                    "session": "sess-1",
                },
            ],
        )

    async def test_sign_device_repairs_current_device_key_mismatch_once(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            def __init__(self):
                self.upload_payloads = []
                self.repaired = False
                self.signature_visible = False

            async def query_keys(self, device_keys, timeout=10000):
                if not self.repaired:
                    return {
                        "device_keys": {
                            "@bot:example.org": {
                                "BOT123": {
                                    "keys": {
                                        "ed25519:BOT123": "server-ed25519",
                                        "curve25519:BOT123": "server-curve25519",
                                    },
                                    "signatures": {},
                                }
                            }
                        }
                    }
                signatures = {}
                if self.signature_visible:
                    signatures = {
                        "@bot:example.org": {"ed25519:SELFKEY": "sig"}
                    }
                return {
                    "device_keys": {
                        "@bot:example.org": {
                            "BOT123": {
                                "keys": {
                                    "ed25519:BOT123": "local-ed25519",
                                    "curve25519:BOT123": "local-curve25519",
                                },
                                "signatures": signatures,
                            }
                        }
                    }
                }

            async def upload_signatures(self, signatures):
                self.upload_payloads.append(signatures)
                self.signature_visible = True
                return {"failures": {}}

        class DummyOlm:
            def get_identity_keys(self):
                return {
                    "ed25519:BOT123": "local-ed25519",
                    "curve25519:BOT123": "local-curve25519",
                }

        client = DummyClient()

        async def repair_current_device_keys():
            client.repaired = True

        cross_signing = cross_signing_module.CrossSigning(
            client=client,
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
            repair_current_device_keys=repair_current_device_keys,
        )
        cross_signing._self_signing_priv = b"1" * 32
        cross_signing._self_signing_key = "SELFKEY"
        cross_signing._sign = lambda priv, payload: "sig"

        ok = await cross_signing.sign_device("BOT123")

        self.assertTrue(ok)
        self.assertEqual(len(client.upload_payloads), 1)

    async def test_sign_device_skips_republish_when_server_device_keys_are_unchanged(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            def __init__(self):
                self.upload_payloads = []
                self.republish_calls = []
                self.query_count = 0

            async def query_keys(self, device_keys, timeout=10000):
                self.query_count += 1
                signatures = {}
                if self.query_count >= 3:
                    signatures = {
                        "@bot:example.org": {
                            "ed25519:BOT123": "device-self-signature",
                            "ed25519:SELFKEY": "cross-signature",
                        }
                    }
                return {
                    "device_keys": {
                        "@bot:example.org": {
                            "BOT123": {
                                "user_id": "@bot:example.org",
                                "device_id": "BOT123",
                                "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
                                "keys": {
                                    "ed25519:BOT123": "device-ed25519",
                                    "curve25519:BOT123": "device-curve25519",
                                },
                                "signatures": signatures,
                            }
                        }
                    }
                }

            async def upload_signatures(self, signatures):
                self.upload_payloads.append(signatures)
                return {"failures": {}}

            async def upload_keys(self, device_keys=None, one_time_keys=None, fallback_keys=None):
                self.republish_calls.append(device_keys)
                return {"one_time_key_counts": {"signed_curve25519": 50}}

        class DummyOlm:
            def get_identity_keys(self):
                return {
                    "ed25519:BOT123": "device-ed25519",
                    "curve25519:BOT123": "device-curve25519",
                }

        client = DummyClient()
        cross_signing = cross_signing_module.CrossSigning(
            client=client,
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
        )
        cross_signing._self_signing_priv = b"1" * 32
        cross_signing._self_signing_key = "SELFKEY"
        cross_signing._sign = lambda priv, payload: "sig"

        ok = await cross_signing.sign_device("BOT123")

        self.assertTrue(ok)
        self.assertEqual(len(client.upload_payloads), 1)
        self.assertEqual(len(client.republish_calls), 0)

    async def test_sign_master_key_with_device_repairs_current_device_key_mismatch_once(self):
        cross_signing_module = self._load_cross_signing_module()

        class DummyClient:
            def __init__(self):
                self.upload_payloads = []
                self.repaired = False
                self.signature_visible = False

            async def query_keys(self, device_keys, timeout=10000):
                device_payload = {
                    "keys": {
                        "ed25519:BOT123": (
                            "local-ed25519" if self.repaired else "server-ed25519"
                        ),
                        "curve25519:BOT123": (
                            "local-curve25519"
                            if self.repaired
                            else "server-curve25519"
                        ),
                    }
                }
                master_signatures = {"@bot:example.org": {"ed25519:OLD": "old"}}
                if self.signature_visible:
                    master_signatures["@bot:example.org"]["ed25519:BOT123"] = "device-signature"
                return {
                    "device_keys": {"@bot:example.org": {"BOT123": device_payload}},
                    "master_keys": {
                        "@bot:example.org": {
                            "user_id": "@bot:example.org",
                            "usage": ["master"],
                            "keys": {"ed25519:MASTERKEY": "MASTERKEY"},
                            "signatures": master_signatures,
                        }
                    },
                }

            async def upload_signatures(self, signatures):
                self.upload_payloads.append(signatures)
                self.signature_visible = True
                return {"failures": {}}

        class DummyOlm:
            class _Account:
                def sign(self, payload):
                    return types.SimpleNamespace(
                        to_base64=lambda: "device-signature"
                    )

            def __init__(self):
                self._account = self._Account()
                self.device_id = "BOT123"

            def get_identity_keys(self):
                return {
                    "ed25519:BOT123": "local-ed25519",
                    "curve25519:BOT123": "local-curve25519",
                }

        client = DummyClient()

        async def repair_current_device_keys():
            client.repaired = True

        cross_signing = cross_signing_module.CrossSigning(
            client=client,
            user_id="@bot:example.org",
            device_id="BOT123",
            olm_machine=DummyOlm(),
            repair_current_device_keys=repair_current_device_keys,
        )
        cross_signing._master_key = "MASTERKEY"

        ok = await cross_signing.sign_master_key_with_device("@bot:example.org")

        self.assertTrue(ok)
        self.assertEqual(len(client.upload_payloads), 1)


class MatrixKeyBackupCompatTests(unittest.IsolatedAsyncioTestCase):
    async def test_initialize_prefers_configured_key_for_dehydrated_restore_before_ssss(self):
        backup_module = load_module("e2ee.key_backup_backup")

        expected_key = b"D" * 32

        class DummyBackup(backup_module.KeyBackupBackupMixin):
            def __init__(self):
                self._provided_recovery_material_bytes = b"P" * 32
                self._provided_secret_storage_key_bytes = b"P" * 32
                self._backup_auth_data = {}
                self._backup_version = None
                self.used_keys = []
                self.calls = []

            async def _get_current_backup_version(self):
                return "1"

            def _get_valid_local_recovery_key_bytes(self):
                return None

            async def _try_restore_from_dehydrated_device_key(self, key_bytes):
                self.calls.append(("dehydrated", key_bytes))
                return expected_key

            async def _try_restore_from_secret_storage(
                self,
                key_bytes,
                *,
                include_dehydrated=True,
                allow_local_short_circuit=True,
            ):
                self.calls.append(
                    (
                        "ssss",
                        key_bytes,
                        include_dehydrated,
                        allow_local_short_circuit,
                    )
                )
                return b"S" * 32

            def _verify_recovery_key(self, key_bytes, log_mismatch=True):
                return key_bytes == expected_key

            def use_recovery_key_bytes(self, key_bytes, persist=False):
                self.used_keys.append((key_bytes, persist))
                return True

        backup = DummyBackup()
        await backup.initialize()

        self.assertEqual(backup.used_keys, [(expected_key, True)])
        self.assertEqual(backup.calls, [("dehydrated", b"P" * 32)])

    def test_verify_recovery_key_rejects_non_32_byte_key(self):
        backup_module = load_module("e2ee.key_backup_backup")

        class DummyBackup(backup_module.KeyBackupBackupMixin):
            def __init__(self):
                self._backup_auth_data = {"public_key": "dummy"}

        backup = DummyBackup()
        self.assertFalse(backup._verify_recovery_key(b"short", log_mismatch=False))

    async def test_upload_single_key_falls_back_to_bulk_endpoint_on_unrecognized(self):
        backup_module = load_module("e2ee.key_backup_backup")

        class DummyMatrixError(Exception):
            def __init__(self, status, data, message):
                self.status = status
                self.data = data
                super().__init__(message)

        class DummyClient:
            def __init__(self):
                self.calls = []

            async def _request(self, method, endpoint, data=None, **kwargs):
                self.calls.append((method, endpoint, data))
                if endpoint.startswith("/_matrix/client/v3/room_keys/keys/!"):
                    raise DummyMatrixError(
                        404,
                        {"errcode": "M_UNRECOGNIZED", "error": "Unrecognized request"},
                        "Matrix API error: M_UNRECOGNIZED - Unrecognized request (status: 404)",
                    )
                return {}

        class DummyBackup(backup_module.KeyBackupBackupMixin):
            def __init__(self):
                self.client = DummyClient()
                self._backup_version = "1"
                self._encryption_key = b"1" * 32

        backup = DummyBackup()
        ok = await backup.upload_single_key("!room:example.org", "sess1", "secret")

        self.assertTrue(ok)
        self.assertEqual(len(backup.client.calls), 2)
        self.assertEqual(
            backup.client.calls[0][1],
            "/_matrix/client/v3/room_keys/keys/!room:example.org/sess1?version=1",
        )
        self.assertEqual(
            backup.client.calls[1][1],
            "/_matrix/client/v3/room_keys/keys?version=1",
        )
        self.assertEqual(
            set(backup.client.calls[1][2]["rooms"]["!room:example.org"]["sessions"].keys()),
            {"sess1"},
        )

    async def test_upload_single_key_does_not_fall_back_for_other_errors(self):
        backup_module = load_module("e2ee.key_backup_backup")

        class DummyMatrixError(Exception):
            def __init__(self, status, data, message):
                self.status = status
                self.data = data
                super().__init__(message)

        class DummyClient:
            def __init__(self):
                self.calls = []

            async def _request(self, method, endpoint, data=None, **kwargs):
                self.calls.append((method, endpoint, data))
                raise DummyMatrixError(
                    403,
                    {"errcode": "M_FORBIDDEN", "error": "Forbidden"},
                    "Matrix API error: M_FORBIDDEN - Forbidden (status: 403)",
                )

        class DummyBackup(backup_module.KeyBackupBackupMixin):
            def __init__(self):
                self.client = DummyClient()
                self._backup_version = "1"
                self._encryption_key = b"1" * 32

        backup = DummyBackup()
        ok = await backup.upload_single_key("!room:example.org", "sess1", "secret")

        self.assertFalse(ok)
        self.assertEqual(len(backup.client.calls), 1)


if __name__ == "__main__":
    unittest.main()
