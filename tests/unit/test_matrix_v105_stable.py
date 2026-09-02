import unittest

from test_matrix_new_spec_compat import load_module


class MatrixV105RefreshTests(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_requires_and_sends_refresh_token(self):
        mod = load_module("client.auth.session.lifecycle")
        calls = []

        class Client(mod.AuthSessionLifecycleMixin):
            access_token = "old"

            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"access_token": "new"}

        client = Client()
        await client.refresh_access_token("refresh-token")
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[0][1], "/_matrix/client/v3/refresh")
        self.assertEqual(calls[0][2]["data"], {"refresh_token": "refresh-token"})
        self.assertFalse(calls[0][2]["authenticated"])
        self.assertEqual(client.access_token, "new")

        with self.assertRaises(ValueError):
            await client.refresh_access_token("")


class MatrixV105ReferenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_reference_relation_is_not_rewritten(self):
        mod = load_module("client.message.receipts.events.query")
        calls = []

        class Client(mod.MessageEventQueryMixin):
            async def _request(self, method, endpoint, **kwargs):
                calls.append((method, endpoint, kwargs))
                return {"chunk": []}

        await Client().get_event_relations(
            "!room:example.org", "$event", "m.reference"
        )
        self.assertIn("/relations/", calls[0][1])
        self.assertTrue(calls[0][1].endswith("/m.reference"))


if __name__ == "__main__":
    unittest.main()
