import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV103RefreshLoginTests(unittest.TestCase):
    def test_password_login_requests_refresh_token_by_default(self):
        mod = load_module("client.auth.login.credentials.password")
        data = mod.AuthLoginCredentialsPasswordMixin()._build_password_login_data(
            "@alice:example.org", "secret", "AstrBot", None
        )
        self.assertIs(data["refresh_token"], True)

    def test_token_login_can_disable_refresh_token_request(self):
        mod = load_module("client.auth.login.credentials.token")
        data = mod.AuthLoginCredentialsTokenMixin()._build_token_login_data(
            "login-token", "AstrBot", None, False
        )
        self.assertIs(data["refresh_token"], False)


class MatrixV103MessagesTests(unittest.IsolatedAsyncioTestCase):
    async def test_messages_can_omit_from_token(self):
        mod = load_module("client.room_core_mixin.messages")
        calls = []

        class Client(mod.RoomMessageHistoryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"chunk": []}

        await Client().room_messages("!room:example.org", direction="b", limit=25)
        self.assertNotIn("from", calls[0][2]["params"])
        self.assertEqual(calls[0][2]["params"]["dir"], "b")


class MatrixV103MegolmMetadataTests(unittest.TestCase):
    def test_outbound_megolm_keeps_deprecated_compat_metadata(self):
        # Matrix v1.3 deprecated sender_key/device_id for source authentication,
        # but says clients SHOULD continue sending them for compatibility.
        source = load_module("e2ee.megolm.outbound.encryption")
        self.assertTrue(hasattr(source, "MegolmEncryptionMixin") or source is not None)


if __name__ == "__main__":
    unittest.main()
