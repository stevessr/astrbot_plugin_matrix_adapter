import unittest
from urllib.parse import urlparse

from test_matrix_new_spec_compat import load_module


class _FakeCallbackServer:
    async def wait_for_callback(self):
        return "login-token"

    async def stop(self):
        return None


class MatrixV101SsoTests(unittest.IsolatedAsyncioTestCase):
    async def test_named_sso_provider_uses_stable_idp_redirect(self):
        mod = load_module("auth.sso.flow.login.core")
        announced = []

        class Client:
            async def get_login_flows(self):
                return {
                    "flows": [
                        {
                            "type": "m.login.sso",
                            "identity_providers": [
                                {"id": "oidc/example", "name": "Example"}
                            ],
                        }
                    ]
                }

            async def login_token(self, token, device_name, device_id=None):
                return {
                    "access_token": "access",
                    "user_id": "@alice:example.org",
                    "device_id": device_id or "DEVICE",
                }

        class Flow(mod.MatrixSSOLoginMixin):
            async def _prepare_sso_callback(self, state):
                self.callback_server = _FakeCallbackServer()
                return f"https://bot.example/callback?state={state}"

            def _announce_sso_login(self, sso_url, url_callback, show_qr):
                announced.append(sso_url)

        result = await Flow(
            Client(),
            "https://matrix.example",
            "https://bot.example/callback",
        ).login(
            "AstrBot",
            idp_id="oidc/example",
        )

        self.assertEqual(result["access_token"], "access")
        parsed = urlparse(announced[0])
        self.assertEqual(
            parsed.path,
            "/_matrix/client/v3/login/sso/redirect/oidc%2Fexample",
        )

    async def test_unknown_advertised_sso_provider_is_rejected(self):
        mod = load_module("auth.sso.flow.login.core")

        class Client:
            async def get_login_flows(self):
                return {
                    "flows": [
                        {
                            "type": "m.login.sso",
                            "identity_providers": [{"id": "google", "name": "Google"}],
                        }
                    ]
                }

        flow = mod.MatrixSSOLoginMixin(
            Client(),
            "https://matrix.example",
            "https://bot.example/callback",
        )
        with self.assertRaises(ValueError):
            await flow.login("AstrBot", idp_id="github")


class MatrixV101VerificationTests(unittest.TestCase):
    def test_only_modern_sas_key_agreement_is_advertised(self):
        crypto = load_module("constants.crypto")
        self.assertEqual(
            crypto.KEY_AGREEMENT_PROTOCOLS,
            ["curve25519-hkdf-sha256"],
        )

    def test_ready_and_done_verification_events_are_defined(self):
        crypto = load_module("constants.crypto")
        self.assertEqual(crypto.M_KEY_VERIFICATION_READY, "m.key.verification.ready")
        self.assertEqual(crypto.M_KEY_VERIFICATION_DONE, "m.key.verification.done")

    def test_qr_self_verification_methods_and_wire_constants_are_stable(self):
        crypto = load_module("constants.crypto")
        self.assertEqual(crypto.M_QR_CODE_SHOW_V1_METHOD, "m.qr_code.show.v1")
        self.assertEqual(crypto.M_QR_CODE_SCAN_V1_METHOD, "m.qr_code.scan.v1")
        self.assertEqual(crypto.M_RECIPROCATE_V1_METHOD, "m.reciprocate.v1")
        self.assertEqual(crypto.QR_CODE_HEADER, b"MATRIX")
        self.assertEqual(crypto.QR_CODE_VERSION, 0x02)
        self.assertEqual(crypto.QR_CODE_MODE_SELF_VERIFICATION_TRUSTED_MASTER, 0x01)
        self.assertEqual(crypto.QR_CODE_MODE_SELF_VERIFICATION_UNTRUSTED_MASTER, 0x02)


if __name__ == "__main__":
    unittest.main()
