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
    async def test_send_content_adds_thread_reply_fallback_to_root(self):
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

    async def test_send_content_prefers_explicit_reply_for_thread_fallback(self):
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
        self.assertEqual(
            backup.secret_names,
            [
                constants.DEHYDRATED_DEVICE_EVENT,
                constants.MSC2697_DEHYDRATED_DEVICE_EVENT,
            ],
        )


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
                            "DEV123": {"keys": {"curve25519:DEV123": "curve"}}
                        }
                    }
                }

        class DummyOlm:
            is_new_account = False

            def __init__(self):
                self.marked = False

            def get_device_keys(self):
                raise AssertionError("should not build device keys when already present")

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


class MatrixKeyBackupCompatTests(unittest.IsolatedAsyncioTestCase):
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