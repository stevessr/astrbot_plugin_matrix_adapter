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


if __name__ == "__main__":
    unittest.main()
