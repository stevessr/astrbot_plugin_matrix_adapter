import unittest
from urllib.parse import parse_qs, urlsplit

from test_matrix_new_spec_compat import load_module


class StableOAuthAwareCapabilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("client.auth.discovery.capabilities")

    async def test_preferred_sso_flow_is_detected(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            async def _request(self, method, endpoint, **kwargs):
                return {
                    "flows": [
                        {"type": "m.login.password"},
                        {
                            "type": "m.login.sso",
                            "oauth_aware_preferred": True,
                            "identity_providers": [],
                        },
                    ]
                }

        flow = await Client().get_oauth_aware_preferred_sso_flow()
        self.assertIsNotNone(flow)
        self.assertEqual(flow["type"], "m.login.sso")

    async def test_3pid_changes_defaults_true_and_honours_false(self):
        class Client(self.mod.AuthDiscoveryCapabilitiesMixin):
            disabled = False

            async def _request(self, method, endpoint, **kwargs):
                if self.disabled:
                    return {
                        "capabilities": {"m.3pid_changes": {"enabled": False}}
                    }
                return {"capabilities": {}}

        client = Client()
        self.assertTrue(await client.can_change_3pids())
        client.disabled = True
        self.assertFalse(await client.can_change_3pids())


class StableOAuthFlowSelectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("auth.oauth2.flow.login.core")

    async def test_headless_login_selects_device_grant(self):
        seen = {}

        class Flow(self.mod.MatrixOAuth2FlowLoginMixin):
            redirect_uri = None
            callback_server = None

            async def _discover_oauth_endpoints(self):
                return {
                    "authorization_endpoint": "https://auth.example/authorize",
                    "token_endpoint": "https://auth.example/token",
                }

            def supports_device_authorization_grant(self):
                return True

            async def login_device(self, *, on_verification=None):
                seen["callback"] = on_verification
                return {"access_token": "token", "user_id": "@bot:example.org"}

        callback = object()
        response = await Flow().login(on_device_verification=callback)
        self.assertEqual(response["access_token"], "token")
        self.assertIs(seen["callback"], callback)


class StableOAuthAwareSSOTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mod = load_module("auth.sso.flow.login.core")

    async def test_sso_redirect_carries_stable_action(self):
        urls = []

        class Callback:
            async def wait_for_callback(self):
                return "login-token"

            async def stop(self):
                return None

        class Client:
            async def get_login_flows(self):
                return {
                    "flows": [
                        {"type": "m.login.sso", "oauth_aware_preferred": True}
                    ]
                }

            async def login_token(self, **kwargs):
                return {"user_id": "@bot:example.org", "device_id": "DEVICE"}

        class SSO(self.mod.MatrixSSOLoginMixin):
            async def _prepare_sso_callback(self, state):
                self.callback_server = Callback()
                return f"https://bot.example/callback?state={state}"

            def _announce_sso_login(self, sso_url, url_callback, show_qr):
                urls.append(sso_url)

        sso = SSO(
            Client(),
            "https://matrix.example.org",
            redirect_uri="https://bot.example/callback",
        )
        await sso.login("AstrBot", action="register")
        query = parse_qs(urlsplit(urls[0]).query)
        self.assertEqual(query["action"], ["register"])
        self.assertIn("redirectUrl", query)

    async def test_invalid_sso_action_is_rejected_before_network(self):
        sso = self.mod.MatrixSSOLoginMixin(
            object(),
            "https://matrix.example.org",
            redirect_uri="https://bot.example/callback",
        )
        with self.assertRaises(ValueError):
            await sso.login("AstrBot", action="delete")


if __name__ == "__main__":
    unittest.main()
