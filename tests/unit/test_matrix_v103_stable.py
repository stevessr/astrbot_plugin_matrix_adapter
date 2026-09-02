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
        # v1.3 says sender_key/device_id SHOULD still be emitted for compatibility,
        # despite being deprecated for authenticating the event source.
        mod = load_module("e2ee.megolm.outbound.encryption")

        class Ciphertext:
            def to_base64(self):
                return "ciphertext"

        class Session:
            session_id = "session"

            def encrypt(self, payload):
                self.last_payload = payload
                return Ciphertext()

            def pickle(self, key):
                return "pickle"

        class CurveKey:
            def to_base64(self):
                return "curve-key"

        class Account:
            curve25519_key = CurveKey()

        class Store:
            def save_megolm_outbound(self, room_id, pickle):
                pass

            def record_megolm_outbound_message(self, room_id, session_id):
                pass

        machine = mod.OlmMachineMegolmOutboundEncryptionMixin()
        machine._megolm_outbound = {"!room:example.org": Session()}
        machine._megolm_inbound = {"session": object()}
        machine._pickle_key = b"pickle-key"
        machine._account = Account()
        machine.device_id = "DEVICE"
        machine.store = Store()

        encrypted = machine.encrypt_megolm(
            "!room:example.org", "m.room.message", {"body": "hello"}
        )
        self.assertEqual(encrypted["sender_key"], "curve-key")
        self.assertEqual(encrypted["device_id"], "DEVICE")
        self.assertEqual(encrypted["session_id"], "session")


if __name__ == "__main__":
    unittest.main()
