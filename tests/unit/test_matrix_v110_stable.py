import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV110SupportDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_support_uses_well_known_endpoint_without_auth(self):
        mod = load_module("client.auth.discovery.capabilities")
        calls = []

        class Client(mod.AuthDiscoveryCapabilitiesMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {
                    "contacts": [{"matrix_id": "@admin:example.org", "role": "m.role.admin"}],
                    "support_page": "https://example.org/support",
                    "org.example.extra": True,
                }

        response = await Client().get_server_support()
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[0][1], "/.well-known/matrix/support")
        self.assertFalse(calls[0][2]["authenticated"])
        self.assertTrue(response["org.example.extra"])


class MatrixV110RelationsTests(unittest.IsolatedAsyncioTestCase):
    async def test_recursive_relations_emit_stable_query_flag(self):
        mod = load_module("client.message.receipts.events.query")
        calls = []

        class Client(mod.MessageEventQueryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"chunk": []}

        await Client().get_event_relations(
            "!room:example.org",
            "$event",
            "m.reference",
            recurse=True,
        )
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[0][2]["params"]["recurse"], "true")

    async def test_recursive_relations_flag_can_be_omitted(self):
        mod = load_module("client.message.receipts.events.query")
        calls = []

        class Client(mod.MessageEventQueryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"chunk": []}

        await Client().get_event_relations(
            "!room:example.org",
            "$event",
            "m.annotation",
        )
        self.assertNotIn("recurse", calls[0][2]["params"])


class MatrixV110ErasureTests(unittest.IsolatedAsyncioTestCase):
    async def test_deactivate_account_preserves_stable_erase_flag(self):
        mod = load_module("client.account_mixin.account")
        calls = []

        class Client(mod.AccountOperationsMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"id_server_unbind_result": "success"}

        await Client().deactivate_account(
            auth={"type": "m.login.password", "session": "uia"},
            erase=True,
        )
        self.assertEqual(calls[0][1], "/_matrix/client/v3/account/deactivate")
        self.assertTrue(calls[0][2]["data"]["erase"])


if __name__ == "__main__":
    unittest.main()
