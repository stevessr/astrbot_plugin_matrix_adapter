import base64
import importlib
import sys
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

    class ComponentType:
        Unknown = "unknown"

    message_components.BaseMessageComponent = BaseMessageComponent
    message_components.Plain = Plain
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
        f"{PACKAGE_NAME}.e2ee": REPO_ROOT / "e2ee",
        f"{PACKAGE_NAME}.receiver": REPO_ROOT / "receiver",
        f"{PACKAGE_NAME}.receiver.handlers": REPO_ROOT / "receiver" / "handlers",
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

        expected_key = b"K" * 32
        encoded_key = base64.b64encode(expected_key).decode("ascii")

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


if __name__ == "__main__":
    unittest.main()