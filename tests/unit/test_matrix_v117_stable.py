import asyncio
import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV117OAuthUIATests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.uia = load_module("e2ee.signing.upload.uia")
        self.auth = load_module("e2ee.signing.crypto.auth")

    @staticmethod
    def _oauth_challenge(error_cls, *, url="https://auth.example/account/reset"):
        return error_cls(
            401,
            {
                "session": "uia-session",
                "flows": [{"stages": ["m.oauth"]}],
                "params": {"m.oauth": {"url": url}},
            },
            "UIA required",
        )

    async def test_cross_signing_oauth_uia_uses_session_only_completion(self):
        calls = []
        approvals = []
        uia = self.uia

        class Client:
            async def upload_signing_keys(self, **kwargs):
                calls.append(kwargs)
                if len(calls) == 1:
                    raise MatrixV117OAuthUIATests._oauth_challenge(uia.MatrixAPIError)
                return {}

        class Signing(
            self.uia.CrossSigningUploadUIAMixin,
            self.auth.CrossSigningCryptoAuthMixin,
        ):
            password = "legacy-password"
            pending_oauth_uia = None
            _OAUTH_UIA_POLL_INTERVAL_SECONDS = 0
            _OAUTH_UIA_MAX_ATTEMPTS = 1

            def __init__(self):
                self.client = Client()
                self.user_id = "@bot:example.org"
                self.oauth_uia_callback = lambda approval: approvals.append(approval)

        signing = Signing()
        await signing._upload_signing_keys_with_uia(
            master_key={"master": True},
            self_signing_key={"self": True},
            user_signing_key={"user": True},
        )

        self.assertEqual(len(calls), 2)
        self.assertNotIn("auth", calls[0])
        self.assertEqual(calls[1]["auth"], {"session": "uia-session"})
        self.assertNotIn("type", calls[1]["auth"])
        self.assertEqual(
            approvals,
            [{"session": "uia-session", "url": "https://auth.example/account/reset"}],
        )
        self.assertIsNone(signing.pending_oauth_uia)

    async def test_malformed_advertised_oauth_uia_does_not_downgrade_to_password(self):
        calls = []
        uia = self.uia

        class Client:
            async def upload_signing_keys(self, **kwargs):
                calls.append(kwargs)
                raise MatrixV117OAuthUIATests._oauth_challenge(
                    uia.MatrixAPIError,
                    url="javascript:alert(1)",
                )

        class Signing(
            self.uia.CrossSigningUploadUIAMixin,
            self.auth.CrossSigningCryptoAuthMixin,
        ):
            password = "must-not-be-used"
            pending_oauth_uia = None

            def __init__(self):
                self.client = Client()
                self.user_id = "@bot:example.org"
                self.oauth_uia_callback = None

        with self.assertRaises(RuntimeError):
            await Signing()._upload_signing_keys_with_uia(
                master_key={},
                self_signing_key={},
                user_signing_key={},
            )
        self.assertEqual(len(calls), 1)
        self.assertNotIn("auth", calls[0])

    async def test_non_oauth_uia_keeps_dummy_fallback(self):
        calls = []
        uia = self.uia

        class Client:
            async def upload_signing_keys(self, **kwargs):
                calls.append(kwargs)
                if len(calls) == 1:
                    raise uia.MatrixAPIError(
                        401,
                        {
                            "session": "dummy-session",
                            "flows": [{"stages": ["m.login.dummy"]}],
                        },
                        "UIA required",
                    )
                return {}

        class Signing(
            self.uia.CrossSigningUploadUIAMixin,
            self.auth.CrossSigningCryptoAuthMixin,
        ):
            password = None

            def __init__(self):
                self.client = Client()
                self.user_id = "@bot:example.org"
                self.oauth_uia_callback = None

        await Signing()._upload_signing_keys_with_uia(
            master_key={},
            self_signing_key={},
            user_signing_key={},
        )
        self.assertEqual(
            calls[1]["auth"],
            {"type": "m.login.dummy", "session": "dummy-session"},
        )


class MatrixV117OneTimeKeyCountTests(unittest.IsolatedAsyncioTestCase):
    async def test_omitted_otk_count_is_dispatched_as_zero(self):
        mod = load_module("sync.sync_lib.dispatch.routing.fields")
        received = []

        async def on_count(counts, unused_fallback_key_types):
            received.append((counts, unused_fallback_key_types))

        class Router(mod.MatrixSyncManagerEventRoutingFieldsMixin):
            on_to_device_event = None
            on_device_lists = None
            on_presence_event = None
            on_account_data = None
            on_device_one_time_keys_count = staticmethod(on_count)

            async def _run_callback_with_guard(self, _name, callback, *args):
                await callback(*args)

        tasks = []
        Router()._dispatch_global_fields({}, tasks)
        await asyncio.gather(*tasks)
        self.assertEqual(received, [({}, None)])


class MatrixV117IntentionalMentionTests(unittest.IsolatedAsyncioTestCase):
    async def test_room_message_without_mentions_still_emits_empty_m_mentions(self):
        mod = load_module("sender.events.common")
        calls = []

        class Client:
            async def send_message(self, **kwargs):
                calls.append(kwargs)
                return {"event_id": "$event:example.org"}

        content = {"msgtype": "m.text", "body": "hello without mentions"}
        await mod.send_content(
            Client(),
            content,
            "!room:example.org",
            None,
            None,
            False,
            False,
            None,
        )
        self.assertEqual(calls[0]["content"]["m.mentions"], {})

    async def test_existing_intentional_mentions_are_preserved(self):
        mod = load_module("sender.events.common")
        calls = []

        class Client:
            async def send_message(self, **kwargs):
                calls.append(kwargs)
                return {}

        mentions = {"user_ids": ["@alice:example.org"]}
        await mod.send_content(
            Client(),
            {"msgtype": "m.text", "body": "hi", "m.mentions": mentions},
            "!room:example.org",
            None,
            None,
            False,
            False,
            None,
        )
        self.assertEqual(calls[0]["content"]["m.mentions"], mentions)


class MatrixV117ResourceLimitTests(unittest.TestCase):
    def test_resource_limit_error_exposes_admin_contact(self):
        mod = load_module("client.base.errors")
        error = mod.MatrixAPIError(
            403,
            {
                "errcode": "M_RESOURCE_LIMIT_EXCEEDED",
                "error": "disk quota reached",
                "admin_contact": "mailto:admin@example.org",
            },
            "disk quota reached",
        )
        self.assertTrue(error.is_resource_limit_exceeded)
        self.assertEqual(error.admin_contact, "mailto:admin@example.org")


if __name__ == "__main__":
    unittest.main()
